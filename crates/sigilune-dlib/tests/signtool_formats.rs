//! signtool `/dlib` との結合テスト（クラウドに接続しない）。
//!
//! テスト用のローカル鍵（ssign の自己署名テスト証明書）で、複数の形式に実際の signtool で署名し、
//! WinVerifyTrust が「署名値は正しく、ルートが信頼されていないだけ」（0x800B0109）と判定することを確かめる。
//! これにより、ダイジェストの受け渡し・署名のバイト順・メモリ所有権・証明書の返却を検証する。
//! Windows SDK（signtool / makeappx）がない環境ではスキップする。

#![cfg(windows)]

use sigilune_core::signtool::{SignOptions, find_signtool, sign};
use sigilune_core::verify::{CERT_E_UNTRUSTEDROOT, inspect};
use std::path::{Path, PathBuf};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sigilune-core/tests/fixtures"
);

/// テスト対象の cdylib を返す。
///
/// `cargo test` は結合テストからリンクできない cdylib をビルドしないため、同じプロファイルで
/// `cargo build -p sigilune-dlib` を実行してから使う（ビルド済みなら即終了する）。
/// 並列実行される各テストからの呼出しは Cargo のビルドロックで直列化される。
///
/// テスト実行ファイルの置き場所（build-dir）と成果物の置き場所は Cargo の版や設定で変わるため、
/// パスを推測せず、Cargo が JSON で報告する成果物のパスを使う。ビルド先は CARGO_TARGET_DIR など
/// テスト実行時と同じ環境変数・設定から Cargo 自身が決める。
fn dlib_path() -> PathBuf {
    let mut cmd = std::process::Command::new(env!("CARGO"));
    cmd.args([
        "build",
        "--quiet",
        "-p",
        "sigilune-dlib",
        "--message-format=json-render-diagnostics",
    ])
    .current_dir(env!("CARGO_MANIFEST_DIR"))
    .stdout(std::process::Stdio::piped())
    // コンパイルエラーなどの診断は stderr に出るので、失敗時に原因が見えるよう流しておく。
    .stderr(std::process::Stdio::inherit());
    // テストバイナリと同じプロファイル（debug / release）の dlib を使う。
    if !cfg!(debug_assertions) {
        cmd.arg("--release");
    }
    let out = cmd
        .output()
        .expect("starting cargo build for sigilune-dlib");
    assert!(out.status.success(), "cargo build -p sigilune-dlib failed");
    let dll = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == "sigilune_dlib")
        .flat_map(|m| {
            m["filenames"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
        })
        .filter_map(|f| f.as_str().map(PathBuf::from))
        .find(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")))
        .expect("cargo did not report sigilune_dlib.dll");
    assert!(dll.is_file(), "missing {}", dll.display());
    dll
}

fn work_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("signtool_formats")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn metadata(dir: &Path) -> PathBuf {
    let fixtures = std::fs::canonicalize(FIXTURES).unwrap();
    let json = serde_json::json!({
        "local_key_pem": fixtures.join("selftest_key.pem"),
        "local_cert": fixtures.join("selftest_cert.der"),
    });
    let path = dir.join("meta.json");
    std::fs::write(&path, json.to_string()).unwrap();
    path
}

/// テスト鍵で署名し、署名値が検証を通る（ルート不信頼だけが残る）ことを確認する。
fn sign_and_check(dir: &Path, files: &[PathBuf]) {
    let Ok(tool) = find_signtool() else {
        eprintln!("skipped: signtool not found");
        return;
    };
    let dlib = dlib_path();
    let meta = metadata(dir);
    sign(
        &SignOptions {
            signtool: &tool,
            dlib: &dlib,
            metadata: Some(&meta),
            // テストでは外部 TSA に依存しない。
            timestamp_url: None,
            description: None,
            description_url: None,
        },
        files,
    )
    .expect("signtool sign");
    for f in files {
        let r = inspect(f).unwrap();
        assert!(r.signed, "{}: not signed", f.display());
        assert_eq!(
            r.status,
            CERT_E_UNTRUSTEDROOT,
            "{}: {}",
            f.display(),
            r.status_text()
        );
        assert_eq!(
            r.signer.as_deref(),
            Some("ssign selftest"),
            "{}",
            f.display()
        );
    }
}

#[test]
fn signs_pe_msi_and_powershell() {
    let dir = work_dir("basic");
    let exe = dir.join("hello.exe");
    std::fs::copy(Path::new(FIXTURES).join("hello.exe"), &exe).unwrap();
    let msi = dir.join("test.msi");
    std::fs::copy(Path::new(FIXTURES).join("test.msi"), &msi).unwrap();
    let ps1 = dir.join("script.ps1");
    std::fs::write(&ps1, "Write-Output 'Sigilune'\r\n").unwrap();
    sign_and_check(&dir, &[exe, msi, ps1]);
}

#[test]
fn signs_msix() {
    let Ok(tool) = find_signtool() else { return };
    let makeappx = tool.with_file_name("makeappx.exe");
    if !makeappx.is_file() {
        eprintln!("skipped: makeappx not found");
        return;
    }
    let dir = work_dir("msix");
    let content = dir.join("content");
    std::fs::create_dir_all(&content).unwrap();
    // MSIX の Publisher は署名証明書の主体名と完全一致している必要がある。
    std::fs::write(
        content.join("AppxManifest.xml"),
        r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Sigilune.Test" Publisher="CN=ssign selftest, O=ssign selftest, C=FR" Version="1.0.0.0" ProcessorArchitecture="neutral" />
  <Properties>
    <DisplayName>Sigilune Test</DisplayName>
    <PublisherDisplayName>Sigilune</PublisherDisplayName>
    <Logo>logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
</Package>
"#,
    )
    .unwrap();
    // 1x1 の透過 PNG。
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    std::fs::write(content.join("logo.png"), PNG).unwrap();
    let msix = dir.join("test.msix");
    let status = std::process::Command::new(&makeappx)
        .args(["pack", "/o", "/nv", "/d"])
        .arg(&content)
        .arg("/p")
        .arg(&msix)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "makeappx failed");
    sign_and_check(&dir, &[msix]);
}
