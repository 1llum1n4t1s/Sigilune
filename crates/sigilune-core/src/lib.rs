//! Sigilune の共通部。
//!
//! Certum SimplySign のクラウド証明書で Authenticode 署名するために、次を提供する。
//! - [`credential`] : アカウントのメールと TOTP 登録情報（otpauth URI）を Windows 資格情報マネージャーで保持する
//! - [`session`]    : OAuth トークンと署名用証明書を DPAPI で保護してプロセス間で共有し、TOTP の再利用を防ぐ
//! - [`signer`]     : ダイジェスト署名のバックエンド（クラウド／テスト用ローカル鍵）と中間証明書
//! - [`signtool`]   : Windows SDK の signtool を `/dlib` 付きで起動する
//! - [`verify`]     : WinVerifyTrust による署名者・タイムスタンプの検証
//! - [`manifest`]   : ClickOnce / VSTO マニフェストの XML 署名（補助ツール sigilune-manifest.exe を呼ぶ）
//!
//! クラウドとの HTTPS 通信は `ssign-core`（MIT, Le-Syl21/ssign）の公開関数に任せる。
//! そのトークンキャッシュは平文ファイルのため使わず、本 crate のセッション層で置き換える。
//!
//! Windows 専用。DPAPI・資格情報マネージャー・WinVerifyTrust・signtool に依存する。

#![cfg(windows)]

pub mod cert;
pub mod credential;
pub mod dpapi;
pub mod manifest;
pub mod paths;
pub mod session;
pub mod signer;
pub mod signtool;
pub mod verify;
mod wide;

/// RFC 3161 タイムスタンプの既定値。Certum の証明書には Certum の TSA を使う。
pub const DEFAULT_TIMESTAMP_URL: &str = "http://time.certum.pl";
