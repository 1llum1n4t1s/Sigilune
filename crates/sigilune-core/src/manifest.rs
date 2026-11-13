//! ClickOnce / VSTO マニフェスト（.manifest / .application / .vsto）の署名と検証。
//!
//! マニフェストの署名は Authenticode（signtool）ではなく XML 署名で、正規化・公開鍵トークン・
//! 発行者鍵ハッシュの計算を ClickOnce の実装と一致させる必要がある。そのため本体は
//! MSBuild の実装（mansign2.cs, MIT）を移植した .NET Framework 製の補助ツール `sigilune-manifest.exe`
//! が担い、Sigilune は「ログイン・証明書の受け渡し・ダイジェスト署名（`sigilune sign-hash`）」を受け持つ。

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// 補助ツールの場所。`SIGILUNE_MANIFEST_TOOL` があればそれ、なければこの exe と同じフォルダーの `sigilune-manifest.exe`。
pub fn find_tool() -> Result<PathBuf> {
    crate::paths::env_or_beside_exe(
        "SIGILUNE_MANIFEST_TOOL",
        "sigilune-manifest.exe",
        " (it ships in the Sigilune zip)",
    )
}

/// マニフェスト署名のオプション。
pub struct SignManifestOptions<'a> {
    pub tool: &'a Path,
    /// ダイジェスト署名に呼び戻す sigilune.exe（通常は実行中の exe 自身）。
    pub sigilune: &'a Path,
    /// 署名者証明書（DER ファイル）。
    pub certificate: &'a Path,
    /// X509Data に入れる中間証明書（DER ファイル）。
    pub intermediates: &'a [PathBuf],
    /// RFC 3161 タイムスタンプサーバー。`None` はタイムスタンプなし（テスト用）。
    pub timestamp_url: Option<&'a str>,
    pub description: Option<&'a str>,
    pub description_url: Option<&'a str>,
    /// 先に署名し、`files` の参照（サイズ・ダイジェスト・公開鍵トークン）を合わせるアプリケーション マニフェスト。
    pub application: Option<&'a Path>,
}

/// 補助ツールで署名する。出力は呼出し元のコンソールへそのまま流す。
pub fn sign(opts: &SignManifestOptions, files: &[PathBuf]) -> Result<()> {
    let mut cmd = Command::new(opts.tool);
    cmd.arg("sign")
        .arg("--sigilune")
        .arg(opts.sigilune)
        .arg("--cert")
        .arg(opts.certificate);
    for i in opts.intermediates {
        cmd.arg("--intermediate").arg(i);
    }
    match opts.timestamp_url {
        Some(url) => {
            cmd.args(["--timestamp-url", url]);
        }
        None => {
            cmd.arg("--no-timestamp");
        }
    }
    if let Some(d) = opts.description {
        cmd.args(["--description", d]);
    }
    if let Some(u) = opts.description_url {
        cmd.args(["--description-url", u]);
    }
    if let Some(a) = opts.application {
        cmd.arg("--application").arg(a);
    }
    cmd.args(files);
    run(cmd, opts.tool)
}

/// 補助ツール（.NET Framework の ClickOnce 検証）で検証する。
pub fn verify(
    tool: &Path,
    files: &[PathBuf],
    signer: Option<&str>,
    allow_no_timestamp: bool,
    no_revocation: bool,
) -> Result<()> {
    let mut cmd = Command::new(tool);
    cmd.arg("verify");
    if let Some(s) = signer {
        cmd.args(["--signer", s]);
    }
    if allow_no_timestamp {
        cmd.arg("--allow-no-timestamp");
    }
    if no_revocation {
        cmd.arg("--no-revocation");
    }
    cmd.args(files);
    run(cmd, tool)
}

fn run(mut cmd: Command, tool: &Path) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("starting {}", tool.display()))?;
    if !status.success() {
        bail!(
            "sigilune-manifest failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// 署名用の作業フォルダー（証明書の受け渡し用）。破棄時に中身ごと消す。
pub struct WorkDir(PathBuf);

impl WorkDir {
    pub fn create() -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("sigilune-manifest-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self(dir))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        // 中身は公開証明書だけ（秘密情報なし）。消せなくても署名結果には影響しない。
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 16 進（64 文字）または Base64 の SHA-256 ダイジェストを読む。
pub fn parse_digest(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    let bytes = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..32)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()?
    } else {
        base64_decode(s).context("the digest is neither 64 hex digits nor Base64")?
    };
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("a SHA-256 digest is 32 bytes (got {})", v.len()))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// 標準 Base64（パディングあり）。
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = B64
            .iter()
            .position(|&x| x == c)
            .with_context(|| format!("invalid Base64 character {:?}", c as char))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            let e = base64_encode(data);
            assert_eq!(base64_decode(&e).unwrap(), data);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
    }

    #[test]
    fn parses_hex_and_base64_digests() {
        let d: [u8; 32] = core::array::from_fn(|i| i as u8);
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_digest(&hex).unwrap(), d);
        assert_eq!(parse_digest(&hex.to_uppercase()).unwrap(), d);
        assert_eq!(parse_digest(&base64_encode(&d)).unwrap(), d);
        assert!(parse_digest("abcd").is_err());
        assert!(parse_digest(&base64_encode(&[0u8; 20])).is_err());
    }
}
