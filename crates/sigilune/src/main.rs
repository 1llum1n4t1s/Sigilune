//! sigilune: Certum SimplySign のクラウド証明書で、signtool が扱える全形式に Authenticode 署名する CLI。
//!
//! 利用者向けの出力は英語（公開 OSS のため）、コードコメントは日本語で書く。
//! 秘密値（otpauth URI・TOTP コード・トークン）は表示しない。

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use sigilune_core::cert::Cert;
use sigilune_core::session::{self, LoginPolicy};
use sigilune_core::{DEFAULT_TIMESTAMP_URL, credential, signtool, verify};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "sigilune",
    version,
    about = "Authenticode-sign any format signtool supports with a Certum SimplySign cloud certificate"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register the Certum account e-mail and TOTP seed in Windows Credential Manager
    Setup(SetupArgs),
    /// Log in to the Certum cloud now (reuses a cached session when still valid)
    Login(JsonFlag),
    /// Show the registration and cached session without contacting Certum
    Status(JsonFlag),
    /// Delete the cached session (and, with --forget, the stored registration)
    Logout {
        /// Also delete the account and TOTP seed from Credential Manager
        #[arg(long)]
        forget: bool,
    },
    /// Sign files with signtool + the Sigilune dlib, then verify signer and timestamp
    Sign(SignArgs),
    /// Verify Authenticode signatures (signer, timestamp)
    Verify(VerifyArgs),
    /// Show (or export) the signing certificate of the current session
    Cert {
        /// Write the certificate (DER) to this file
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        json: JsonFlag,
    },
}

#[derive(Args)]
struct JsonFlag {
    /// Print machine-readable JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SetupArgs {
    /// Certum account e-mail (the SimplySign login ID)
    #[arg(long)]
    email: Option<String>,
    /// Read the e-mail and otpauth URI from a JSON file instead of prompting
    #[arg(long, requires_all = ["email_pointer", "uri_pointer"])]
    from_json: Option<PathBuf>,
    /// JSON pointer to the e-mail inside --from-json (e.g. /certum/email)
    #[arg(long)]
    email_pointer: Option<String>,
    /// JSON pointer to the otpauth URI inside --from-json (e.g. /certum/totp_uri)
    #[arg(long)]
    uri_pointer: Option<String>,
}

#[derive(Args)]
struct SignArgs {
    /// Files to sign (any format signtool supports: exe, dll, msi, msix, appx, cab, cat, ps1, ...)
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// RFC 3161 timestamp server
    #[arg(long, default_value = DEFAULT_TIMESTAMP_URL)]
    timestamp_url: String,
    /// Replace an existing signature instead of refusing
    #[arg(long)]
    replace: bool,
    /// Description shown in the UAC prompt (signtool /d)
    #[arg(long)]
    description: Option<String>,
    /// URL for the description (signtool /du)
    #[arg(long)]
    description_url: Option<String>,
    /// Do not log in; fail unless a cached session exists
    #[arg(long)]
    no_login: bool,
    #[command(flatten)]
    json: JsonFlag,
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(required = true)]
    files: Vec<PathBuf>,
    /// Require this signer common name (exact match)
    #[arg(long)]
    signer: Option<String>,
    /// Accept signatures without an RFC 3161 timestamp
    #[arg(long)]
    allow_no_timestamp: bool,
    #[command(flatten)]
    json: JsonFlag,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sigilune: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Setup(a) => setup(a),
        Command::Login(j) => login(j.json),
        Command::Status(j) => status(j.json),
        Command::Logout { forget } => logout(forget),
        Command::Sign(a) => sign(a),
        Command::Verify(a) => verify_cmd(a),
        Command::Cert { out, json } => cert(out, json.json),
    }
}

fn setup(a: SetupArgs) -> Result<()> {
    let (email, uri): (String, Zeroizing<String>) = if let Some(path) = &a.from_json {
        let raw = Zeroizing::new(
            std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        );
        let v: serde_json::Value = serde_json::from_slice(&raw).context("the file is not JSON")?;
        let get = |p: &str| -> Result<String> {
            v.pointer(p)
                .and_then(|x| x.as_str())
                .map(str::to_owned)
                .with_context(|| format!("no string at JSON pointer {p}"))
        };
        let email = match &a.email {
            Some(e) => e.clone(),
            None => get(a.email_pointer.as_deref().unwrap_or_default())?,
        };
        (
            email,
            Zeroizing::new(get(a.uri_pointer.as_deref().unwrap_or_default())?),
        )
    } else {
        let email = a
            .email
            .clone()
            .context("--email is required (or use --from-json)")?;
        // 秘密値は引数に取らない（プロセス一覧・履歴に残るため）。対話時は非表示入力、それ以外は標準入力から読む。
        let uri = if std::io::stdin().is_terminal() {
            Zeroizing::new(rpassword::prompt_password(
                "otpauth:// URI (or Base32 seed), input hidden: ",
            )?)
        } else {
            let mut s = Zeroizing::new(String::new());
            std::io::stdin().read_to_string(&mut s)?;
            s
        };
        (email, uri)
    };
    credential::store(&email, uri.trim())?;
    // 登録を変えたら古いセッションは使わない。
    session::clear_cache()?;
    println!(
        "Stored the Certum registration for {} in Credential Manager ({}).",
        email.trim(),
        credential::target()
    );
    Ok(())
}

fn session_json(s: &session::Session) -> Result<serde_json::Value> {
    let c = Cert::from_der(s.certificate_der())?;
    Ok(serde_json::json!({
        "email": s.email(),
        "expires_at": s.expires_at(),
        "certificate": cert_json(&c),
    }))
}

fn cert_json(c: &Cert) -> serde_json::Value {
    serde_json::json!({
        "subject": c.common_name(),
        "issuer": c.issuer_common_name(),
        "thumbprint": c.thumbprint(),
        "not_after": c.not_after(),
    })
}

fn login(json: bool) -> Result<()> {
    let s = session::acquire(LoginPolicy::AllowLogin)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&session_json(&s)?)?);
    } else {
        let c = Cert::from_der(s.certificate_der())?;
        let left = s.expires_at().saturating_sub(now());
        println!(
            "Session ready for {} (about {} min left).",
            s.email(),
            left / 60
        );
        println!(
            "Certificate: {} (issued by {}, expires {} UTC)",
            c.common_name(),
            c.issuer_common_name(),
            c.not_after()
        );
    }
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn status(json: bool) -> Result<()> {
    let cred = credential::load()?;
    let cache = session::cache_status()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "credential_target": credential::target(),
                "registered": cred.is_some(),
                "email": cred.as_ref().map(|c| c.email.clone()),
                "session": cache,
            }))?
        );
        return Ok(());
    }
    match &cred {
        Some(c) => println!("Registration: {} ({})", c.email, credential::target()),
        None => println!("Registration: none (run `sigilune setup`)"),
    }
    match &cache {
        Some(s) if s.usable => println!(
            "Session: cached for {} ({} min left)",
            s.email,
            s.seconds_left / 60
        ),
        Some(s) => println!("Session: expired cache for {}", s.email),
        None => println!("Session: none"),
    }
    Ok(())
}

fn logout(forget: bool) -> Result<()> {
    let removed = session::clear_cache()?;
    println!(
        "{}",
        if removed {
            "Deleted the cached session."
        } else {
            "No cached session."
        }
    );
    if forget {
        let removed = credential::delete()?;
        println!(
            "{}",
            if removed {
                "Deleted the stored registration."
            } else {
                "No stored registration."
            }
        );
    }
    Ok(())
}

/// 署名対象の確認。存在・重複・既存署名を確かめ、絶対パスへ揃える。
fn prepare_targets(files: &[PathBuf], replace: bool) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for f in files {
        let abs = std::path::absolute(f).with_context(|| format!("resolving {}", f.display()))?;
        if !abs.is_file() {
            bail!("not a file: {}", abs.display());
        }
        if out
            .iter()
            .any(|p| p.as_os_str().eq_ignore_ascii_case(abs.as_os_str()))
        {
            continue;
        }
        let r = verify::inspect(&abs)?;
        if r.status == verify::TRUST_E_SUBJECT_FORM_UNKNOWN {
            bail!("signtool cannot sign this format: {}", abs.display());
        }
        // 既定では未署名のファイルだけを受け付け、意図しない二重署名・上書きを防ぐ。
        if r.signed && !replace {
            bail!(
                "already signed ({}): {} (use --replace to overwrite)",
                r.status_text(),
                abs.display()
            );
        }
        out.push(abs);
    }
    Ok(out)
}

fn sign(a: SignArgs) -> Result<()> {
    let files = prepare_targets(&a.files, a.replace)?;
    let tool = signtool::find_signtool()?;
    let dlib = signtool::find_dlib()?;
    // 先にセッションを確立し、署名者を確定させる（dlib はこのキャッシュを使う）。
    let s = session::acquire(if a.no_login {
        LoginPolicy::CacheOnly
    } else {
        LoginPolicy::AllowLogin
    })?;
    let expected = Cert::from_der(s.certificate_der())?.common_name();
    drop(s);

    signtool::sign(
        &signtool::SignOptions {
            signtool: &tool,
            dlib: &dlib,
            metadata: None,
            timestamp_url: Some(&a.timestamp_url),
            // 入れ子署名（/as）は検証が先頭の署名しか見ないため 0.1 では提供しない。
            append: false,
            description: a.description.as_deref(),
            description_url: a.description_url.as_deref(),
        },
        &files,
    )?;
    report_verification(&files, Some(&expected), false, a.json.json)
}

fn verify_cmd(a: VerifyArgs) -> Result<()> {
    let files: Vec<PathBuf> = a
        .files
        .iter()
        .map(std::path::absolute)
        .collect::<std::io::Result<_>>()?;
    report_verification(
        &files,
        a.signer.as_deref(),
        a.allow_no_timestamp,
        a.json.json,
    )
}

/// 各ファイルの署名を検証し、有効・署名者一致・タイムスタンプありを満たさなければ失敗にする。
fn report_verification(
    files: &[PathBuf],
    signer: Option<&str>,
    allow_no_timestamp: bool,
    json: bool,
) -> Result<()> {
    let mut failures = 0;
    let mut reports = Vec::new();
    for f in files {
        let r = verify::inspect(f)?;
        let problems = problems(&r, signer, allow_no_timestamp);
        if !problems.is_empty() {
            failures += 1;
        }
        if !json {
            let mark = if problems.is_empty() { "OK  " } else { "FAIL" };
            println!(
                "{mark} {} — {}, signer: {}, timestamp: {}",
                display(f),
                r.status_text(),
                r.signer.as_deref().unwrap_or("-"),
                r.timestamp_authority
                    .as_deref()
                    .unwrap_or(if r.timestamped { "yes" } else { "none" })
            );
            for p in &problems {
                println!("     {p}");
            }
        }
        reports.push(serde_json::json!({ "report": r, "problems": problems }));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    }
    if failures > 0 {
        bail!("{failures} of {} file(s) failed verification", files.len());
    }
    Ok(())
}

fn problems(
    r: &verify::SignatureReport,
    signer: Option<&str>,
    allow_no_timestamp: bool,
) -> Vec<String> {
    let mut v = Vec::new();
    if !r.valid {
        v.push(format!("signature is not valid: {}", r.status_text()));
    }
    if let Some(want) = signer
        && r.signer.as_deref() != Some(want)
    {
        v.push(format!("unexpected signer (want {want})"));
    }
    if !allow_no_timestamp && !r.timestamped {
        v.push("no RFC 3161 timestamp".into());
    }
    v
}

fn display(p: &Path) -> String {
    p.display().to_string()
}

fn cert(out: Option<PathBuf>, json: bool) -> Result<()> {
    let s = session::acquire(LoginPolicy::AllowLogin)?;
    let c = Cert::from_der(s.certificate_der())?;
    if let Some(path) = &out {
        std::fs::write(path, c.der()).with_context(|| format!("writing {}", path.display()))?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&cert_json(&c))?);
    } else {
        println!("Subject:    {}", c.common_name());
        println!("Issuer:     {}", c.issuer_common_name());
        println!("Thumbprint: {}", c.thumbprint());
        println!("Expires:    {} UTC", c.not_after());
        if let Some(path) = out {
            println!("Wrote {}", path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(valid: bool, signer: Option<&str>, ts: bool) -> verify::SignatureReport {
        verify::SignatureReport {
            path: "x".into(),
            status: if valid { 0 } else { 0x800B_0109 },
            valid,
            signed: true,
            signer: signer.map(str::to_owned),
            signer_thumbprint: None,
            issuer: None,
            timestamped: ts,
            timestamp_authority: None,
        }
    }

    #[test]
    fn verification_requires_validity_signer_and_timestamp() {
        assert!(problems(&report(true, Some("A"), true), Some("A"), false).is_empty());
        assert_eq!(
            problems(&report(false, Some("A"), true), Some("A"), false).len(),
            1
        );
        assert_eq!(
            problems(&report(true, Some("B"), true), Some("A"), false).len(),
            1
        );
        assert_eq!(
            problems(&report(true, Some("A"), false), Some("A"), false).len(),
            1
        );
        assert!(problems(&report(true, Some("A"), false), Some("A"), true).is_empty());
        assert!(problems(&report(true, None, true), None, false).is_empty());
    }
}
