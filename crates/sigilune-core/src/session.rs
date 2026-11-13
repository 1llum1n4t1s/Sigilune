//! Certum クラウドの署名セッション（OAuth トークン＋署名用カード）を取得・共有する。
//!
//! # 設計
//! - Velopack の `--signTemplate` などはファイルごとに別プロセス（並列もあり得る）で署名を呼ぶ。
//!   Certum は同じ TOTP コードの再利用を拒否するため、ログインは名前付きミューテックスで
//!   ユーザーセッション内に直列化し、得たトークンを DPAPI 保護したファイルで共有する。
//! - キャッシュは ssign-core の平文キャッシュを使わず、本モジュールで保持する。
//! - 最後にログインへ使った TOTP の時間枠を記録し、同じ枠のコードを二度送らない。
//! - ログイン失敗時に自動再試行しない（アカウントロックや不正検知を避ける）。

use crate::{credential, dpapi, paths, wide::wide};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use ssign_core::card::Card;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
use zeroize::Zeroizing;

/// トークンを信頼する期間。実トークンは約30分だが、署名途中で失効しないよう余裕を取る（ssign と同じ）。
const CACHE_TTL_SECS: u64 = 20 * 60;
/// この残り時間を切ったキャッシュは使わない。
const MIN_REMAINING_SECS: u64 = 120;
/// TOTP の時間枠の長さ（Certum は30秒）。
const TOTP_PERIOD: u64 = 30;
/// 時間枠の残りがこれ未満なら次の枠を待つ（CAS のやり取り中にコードが失効しないように）。
const MIN_WINDOW_LEFT_SECS: u64 = 5;
/// ログイン排他の待機上限。
const LOCK_TIMEOUT: Duration = Duration::from_secs(180);

/// ログインを許すかどうか。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoginPolicy {
    /// キャッシュがあればそれを使い、なければ資格情報で1回だけログインする。
    AllowLogin,
    /// キャッシュだけを使う（ネットワーク認証しない）。
    CacheOnly,
}

/// 有効な署名セッション。
pub struct Session {
    // ssign-core が返す reqwest の blocking クライアント（同じ版へ統一される）。
    http: reqwest::blocking::Client,
    token: Zeroizing<String>,
    card: Card,
    cert_der: Vec<u8>,
    email: String,
    expires_at: u64,
}

/// キャッシュファイルの中身（DPAPI で保護して保存する）。
#[derive(Serialize, Deserialize)]
struct CacheDoc {
    v: u32,
    email: String,
    token: String,
    expires_at: u64,
    serial: String,
    cert_pem: String,
}

/// 秘密を含まない補助状態。
#[derive(Serialize, Deserialize, Default)]
struct StateDoc {
    #[serde(default)]
    last_otp_step: u64,
}

/// ネットワークを使わずに分かるセッション状態。
#[derive(Debug, Serialize)]
pub struct CacheStatus {
    pub email: String,
    pub expires_at: u64,
    pub seconds_left: u64,
    pub usable: bool,
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Session {
    pub fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// 失効までの残り秒数（失効済みなら 0）。
    pub fn seconds_left(&self) -> u64 {
        self.expires_at.saturating_sub(now())
    }

    /// クラウド HSM に SHA-256 ダイジェストの署名を依頼し、RSA PKCS#1 v1.5 署名（big-endian）を返す。
    pub fn sign_sha256(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        ssign_core::sign::request(&self.http, &self.token, &self.card, digest)
            .context("the Certum cloud refused or failed the signature request (run `sigilune login` and retry)")
    }

    fn from_cache(doc: CacheDoc) -> Result<Self> {
        let cert_der = ssign_core::authenticode::pem_to_der(doc.cert_pem.as_bytes())?;
        Ok(Self {
            http: ssign_core::client::client()?,
            token: Zeroizing::new(doc.token),
            card: Card {
                serial: doc.serial,
                certificate_pem: doc.cert_pem.into_bytes(),
            },
            cert_der,
            email: doc.email,
            expires_at: doc.expires_at,
        })
    }

    fn save(&self) -> Result<()> {
        let doc = CacheDoc {
            v: 1,
            email: self.email.clone(),
            token: self.token.to_string(),
            expires_at: self.expires_at,
            serial: self.card.serial.clone(),
            cert_pem: String::from_utf8_lossy(&self.card.certificate_pem).into_owned(),
        };
        let json = Zeroizing::new(serde_json::to_vec(&doc)?);
        drop(Zeroizing::new(doc.token));
        let sealed = dpapi::protect(&json)?;
        write_atomic(&paths::session_file()?, &sealed)
    }
}

/// セッションを取得する。
pub fn acquire(policy: LoginPolicy) -> Result<Session> {
    let _lock = NamedMutex::acquire(
        &format!("Local\\Sigilune.Session.{}", paths::instance_tag()),
        LOCK_TIMEOUT,
    )?;
    let cred = credential::load()?;

    if let Some(doc) = read_cache()? {
        let same_account = cred
            .as_ref()
            .is_none_or(|c| c.email.eq_ignore_ascii_case(&doc.email));
        if same_account && doc.expires_at > now() + MIN_REMAINING_SECS {
            return Session::from_cache(doc);
        }
    }

    if policy == LoginPolicy::CacheOnly {
        bail!("no valid Sigilune session is cached (run `sigilune login`)");
    }
    let cred = cred.context("no Certum account is registered (run `sigilune setup`)")?;
    let totp = ssign_core::otp::Totp::parse(cred.otpauth.trim()).map_err(|_| {
        anyhow::anyhow!("the stored TOTP registration is invalid (run `sigilune setup` again)")
    })?;

    let step = wait_for_fresh_totp_window()?;
    let code = Zeroizing::new(totp.code_at(step * TOTP_PERIOD));
    let token = Zeroizing::new(
        ssign_core::auth::login(&cred.email, &code)
            .context("Certum login failed; not retrying automatically (check the PC clock and the TOTP registration)")?
            .0,
    );
    let http = ssign_core::client::client()?;
    let card = ssign_core::card::fetch(&http, &token)
        .context("fetching the SimplySign card and certificate")?;
    let cert_der = ssign_core::authenticode::pem_to_der(&card.certificate_pem)?;
    let session = Session {
        http,
        token,
        card,
        cert_der,
        email: cred.email.clone(),
        expires_at: now() + CACHE_TTL_SECS,
    };
    session.save()?;
    Ok(session)
}

/// キャッシュの状態（ネットワークなし）。
pub fn cache_status() -> Result<Option<CacheStatus>> {
    Ok(read_cache()?.map(|d| {
        let left = d.expires_at.saturating_sub(now());
        CacheStatus {
            email: d.email,
            expires_at: d.expires_at,
            seconds_left: left,
            usable: left > MIN_REMAINING_SECS,
        }
    }))
}

/// キャッシュを削除する（サーバー側のトークン失効はしない）。
pub fn clear_cache() -> Result<bool> {
    let path = paths::session_file()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

fn read_cache() -> Result<Option<CacheDoc>> {
    let path = paths::session_file()?;
    let sealed = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    // 壊れた・他ユーザーのキャッシュは無いものとして扱い、ログインし直す。
    let Ok(plain) = dpapi::unprotect(&sealed) else {
        return Ok(None);
    };
    Ok(serde_json::from_slice::<CacheDoc>(&plain)
        .ok()
        .filter(|d| d.v == 1))
}

/// 未使用で、残り時間が十分な TOTP の時間枠を待って返す。使う枠は先に記録する。
fn wait_for_fresh_totp_window() -> Result<u64> {
    let state_path = paths::state_file()?;
    let mut state: StateDoc = std::fs::read(&state_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    loop {
        let t = now();
        let step = t / TOTP_PERIOD;
        let left = TOTP_PERIOD - t % TOTP_PERIOD;
        if step > state.last_otp_step && left >= MIN_WINDOW_LEFT_SECS {
            // 送信前に記録し、失敗した試行のコードも再利用しない。
            state.last_otp_step = step;
            write_atomic(&state_path, &serde_json::to_vec(&state)?)?;
            return Ok(step);
        }
        std::thread::sleep(Duration::from_secs(left) + Duration::from_millis(200));
    }
}

/// 一時ファイルへ書いてから置き換える。
fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, data).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// ユーザーセッション内の名前付きミューテックス。ドロップで解放する。
struct NamedMutex(HANDLE);

impl NamedMutex {
    fn acquire(name: &str, timeout: Duration) -> Result<Self> {
        let name_w = wide(name);
        // SAFETY: 名前は呼出し中有効。ハンドルはドロップで閉じる。
        unsafe {
            let h = CreateMutexW(std::ptr::null(), 0, name_w.as_ptr());
            if h.is_null() {
                bail!("CreateMutexW failed (0x{:08X})", GetLastError());
            }
            match WaitForSingleObject(h, timeout.as_millis() as u32) {
                // 前の所有者が異常終了していても、キャッシュは原子的に書いているので続行できる。
                WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(h)),
                _ => {
                    CloseHandle(h);
                    bail!("another Sigilune login did not finish in time")
                }
            }
        }
    }
}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        // SAFETY: 取得済みのミューテックスを解放して閉じる。
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
