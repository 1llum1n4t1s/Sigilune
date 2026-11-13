//! Windows SDK の signtool を `/dlib`（ダイジェスト署名 DLL）付きで起動する。
//!
//! ファイル形式ごとの署名データ組立て（PE / MSI / MSIX / CAB / CAT / PowerShell など）は
//! signtool と Windows の SIP に任せ、Sigilune はダイジェストへの署名だけを担う。

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// 実行中 OS のアーキテクチャ名（SDK の bin 配下のフォルダー名）。
fn host_arch() -> &'static str {
    // x64 エミュレーション下の ARM64 でも、dlib と signtool のアーキテクチャを揃えるため
    // 「この exe 自身」のアーキテクチャを基準にする。
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    }
}

/// signtool.exe を探す。`SIGILUNE_SIGNTOOL` があればそれを使い、なければ最新の Windows SDK から選ぶ。
pub fn find_signtool() -> Result<PathBuf> {
    if let Some(p) = crate::paths::file_from_env("SIGILUNE_SIGNTOOL")? {
        return Ok(p);
    }
    let base = std::env::var_os("ProgramFiles(x86)")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"));
    let kits = base.join(r"Windows Kits\10\bin");
    let mut versions: Vec<(Vec<u32>, PathBuf)> = std::fs::read_dir(&kits)
        .with_context(|| {
            format!(
                "the Windows SDK was not found ({}); install it or set SIGILUNE_SIGNTOOL",
                kits.display()
            )
        })?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let ver: Option<Vec<u32>> = name.split('.').map(|s| s.parse().ok()).collect();
            let exe = e.path().join(host_arch()).join("signtool.exe");
            ver.filter(|v| v.len() == 4)
                .filter(|_| exe.is_file())
                .map(|v| (v, exe))
        })
        .collect();
    versions.sort();
    versions.pop().map(|(_, p)| p).with_context(|| {
        format!(
            "signtool.exe ({}) was not found under {}",
            host_arch(),
            kits.display()
        )
    })
}

/// dlib の場所。`SIGILUNE_DLIB` があればそれ、なければこの exe と同じフォルダーの `sigilune_dlib.dll`。
pub fn find_dlib() -> Result<PathBuf> {
    crate::paths::env_or_beside_exe("SIGILUNE_DLIB", "sigilune_dlib.dll", "")
}

/// signtool の署名オプション。
pub struct SignOptions<'a> {
    pub signtool: &'a Path,
    pub dlib: &'a Path,
    /// dlib へ渡すメタデータ（JSON ファイル）。通常は不要。
    pub metadata: Option<&'a Path>,
    /// RFC 3161 タイムスタンプサーバー。`None` はタイムスタンプなし（テスト用）。
    pub timestamp_url: Option<&'a str>,
    /// 追加の署名として付ける（`/as`）。既定は置き換え。
    pub append: bool,
    pub description: Option<&'a str>,
    pub description_url: Option<&'a str>,
}

/// signtool sign を1回で実行する（複数ファイルをまとめる）。出力は呼出し元のコンソールへそのまま流す。
pub fn sign(opts: &SignOptions, files: &[PathBuf]) -> Result<()> {
    if files.is_empty() {
        bail!("no files to sign");
    }
    let mut cmd = Command::new(opts.signtool);
    cmd.arg("sign").args(["/fd", "SHA256"]);
    if let Some(url) = opts.timestamp_url {
        cmd.args(["/td", "SHA256", "/tr", url]);
    }
    cmd.arg("/dlib").arg(opts.dlib);
    if let Some(m) = opts.metadata {
        cmd.arg("/dmdf").arg(m);
    }
    if opts.append {
        cmd.arg("/as");
    }
    if let Some(d) = opts.description {
        cmd.args(["/d", d]);
    }
    if let Some(u) = opts.description_url {
        cmd.args(["/du", u]);
    }
    cmd.args(files);
    let status = cmd
        .status()
        .with_context(|| format!("starting {}", opts.signtool.display()))?;
    if !status.success() {
        bail!(
            "signtool failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}
