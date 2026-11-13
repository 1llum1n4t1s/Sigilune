//! アカウントのメールと TOTP 登録情報（otpauth URI）を Windows 資格情報マネージャーへ保存する。
//!
//! - 種類は汎用資格情報（CRED_TYPE_GENERIC）、保存範囲はこの PC のこのユーザー（LOCAL_MACHINE persist）。
//!   資格情報マネージャーの値は DPAPI でユーザー単位に保護される。
//! - UserName にメール、CredentialBlob に otpauth URI（UTF-8）を入れる。
//! - 値は表示・ログ出力しない。読み出した URI はドロップ時に消去する。

use crate::wide::{from_wide_ptr, wide};
use anyhow::{Result, bail};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW,
    CredWriteW,
};
use zeroize::Zeroizing;

/// 既定の資格情報名。環境変数 `SIGILUNE_CREDENTIAL` で別名にできる（テスト・複数アカウント用）。
pub const DEFAULT_TARGET: &str = "Sigilune/Certum SimplySign";

/// CI 用: アカウントのメールを渡す環境変数。
pub const ENV_EMAIL: &str = "SIGILUNE_EMAIL";
/// CI 用: otpauth URI（または Base32 秘密値）を渡す環境変数。
pub const ENV_TOTP_URI: &str = "SIGILUNE_TOTP_URI";

/// 保存されたアカウント情報。
pub struct StoredCredential {
    pub email: String,
    pub otpauth: Zeroizing<String>,
    /// 環境変数から読んだか（資格情報マネージャーではなく）。
    pub from_env: bool,
}

/// 環境変数（`SIGILUNE_EMAIL` と `SIGILUNE_TOTP_URI`）からアカウント情報を読む。
///
/// GitHub Actions などの CI では資格情報マネージャーへ事前登録できないため、
/// 承認つき Environment の Secrets を環境変数で渡す。片方だけの指定は設定ミスとして拒否する。
pub fn from_env() -> Result<Option<StoredCredential>> {
    parse_env_pair(
        std::env::var(ENV_EMAIL).ok(),
        std::env::var(ENV_TOTP_URI).ok().map(Zeroizing::new),
    )
}

/// 環境変数の組を解釈する（テストのため環境から切り離す）。空文字は未指定とみなす。
fn parse_env_pair(
    email: Option<String>,
    uri: Option<Zeroizing<String>>,
) -> Result<Option<StoredCredential>> {
    let email = email.filter(|s| !s.trim().is_empty());
    let uri = uri.filter(|s| !s.trim().is_empty());
    match (email, uri) {
        (None, None) => Ok(None),
        (Some(email), Some(uri)) => {
            validate_email(&email)?;
            validate_otpauth(&uri)?;
            Ok(Some(StoredCredential {
                email: email.trim().to_owned(),
                otpauth: Zeroizing::new(uri.trim().to_owned()),
                from_env: true,
            }))
        }
        _ => bail!("set both {ENV_EMAIL} and {ENV_TOTP_URI}, or neither"),
    }
}

/// 使用する資格情報名。
pub fn target() -> String {
    std::env::var("SIGILUNE_CREDENTIAL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_TARGET.into())
}

/// otpauth URI（または Base32 秘密値）が Certum の TOTP として解釈できるか確認する。
pub fn validate_otpauth(otpauth: &str) -> Result<()> {
    ssign_core::otp::Totp::parse(otpauth.trim())
        .map(|_| ())
        .map_err(|_| {
            anyhow::anyhow!("the TOTP registration is not a valid otpauth:// URI or Base32 secret")
        })
}

/// メールの最低限の形式確認（空・空白・@ なしを拒否する）。
pub fn validate_email(email: &str) -> Result<()> {
    let e = email.trim();
    if e.is_empty() || e.contains(char::is_whitespace) || !e.contains('@') {
        bail!("the account e-mail looks invalid");
    }
    Ok(())
}

/// 保存（既存は上書き）。
pub fn store(email: &str, otpauth: &str) -> Result<()> {
    validate_email(email)?;
    validate_otpauth(otpauth)?;
    let mut target_w = wide(target());
    let mut user_w = wide(email.trim());
    let secret = Zeroizing::new(otpauth.trim().as_bytes().to_vec());
    let cred = CREDENTIALW {
        Flags: 0,
        Type: CRED_TYPE_GENERIC,
        TargetName: target_w.as_mut_ptr(),
        Comment: null_mut(),
        LastWritten: unsafe { std::mem::zeroed() },
        CredentialBlobSize: secret.len() as u32,
        CredentialBlob: secret.as_ptr() as *mut u8,
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: null_mut(),
        TargetAlias: null_mut(),
        UserName: user_w.as_mut_ptr(),
    };
    // SAFETY: 構造体の各ポインタは呼出し中有効。
    if unsafe { CredWriteW(&cred, 0) } == 0 {
        bail!("CredWriteW failed (0x{:08X})", unsafe { GetLastError() });
    }
    Ok(())
}

/// 読み出し。環境変数が指定されていればそれを優先し、なければ資格情報マネージャーから読む。未登録なら `Ok(None)`。
pub fn load() -> Result<Option<StoredCredential>> {
    if let Some(c) = from_env()? {
        return Ok(Some(c));
    }
    load_stored()
}

/// 資格情報マネージャーからだけ読む。未登録なら `Ok(None)`。
pub fn load_stored() -> Result<Option<StoredCredential>> {
    let target_w = wide(target());
    let mut p: *mut CREDENTIALW = null_mut();
    // SAFETY: 成功時 p は CredFree で解放する。
    unsafe {
        if CredReadW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) == 0 {
            let err = GetLastError();
            if err == ERROR_NOT_FOUND {
                return Ok(None);
            }
            bail!("CredReadW failed (0x{err:08X})");
        }
        let c = &*p;
        let blob = std::slice::from_raw_parts_mut(c.CredentialBlob, c.CredentialBlobSize as usize);
        let otpauth = Zeroizing::new(String::from_utf8_lossy(blob).into_owned());
        blob.fill(0);
        let email = from_wide_ptr(c.UserName);
        CredFree(p as _);
        Ok(Some(StoredCredential {
            email,
            otpauth,
            from_env: false,
        }))
    }
}

/// 削除。未登録なら `Ok(false)`。
pub fn delete() -> Result<bool> {
    let target_w = wide(target());
    // SAFETY: 文字列は呼出し中有効。
    unsafe {
        if CredDeleteW(target_w.as_ptr(), CRED_TYPE_GENERIC, 0) == 0 {
            let err = GetLastError();
            if err == ERROR_NOT_FOUND {
                return Ok(false);
            }
            bail!("CredDeleteW failed (0x{err:08X})");
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_pair_must_be_complete_and_valid() {
        let uri = || {
            Some(Zeroizing::new(
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30"
                    .to_owned(),
            ))
        };
        assert!(parse_env_pair(None, None).unwrap().is_none());
        assert!(
            parse_env_pair(Some(" ".into()), Some(Zeroizing::new(String::new())))
                .unwrap()
                .is_none()
        );
        assert!(parse_env_pair(Some("dev@example.com".into()), None).is_err());
        assert!(parse_env_pair(None, uri()).is_err());
        assert!(parse_env_pair(Some("not-an-email".into()), uri()).is_err());
        let c = parse_env_pair(Some(" dev@example.com ".into()), uri())
            .unwrap()
            .unwrap();
        assert_eq!(c.email, "dev@example.com");
        assert!(c.from_env);
    }

    #[test]
    fn rejects_malformed_inputs() {
        assert!(validate_email("").is_err());
        assert!(validate_email("no-at-sign").is_err());
        assert!(validate_email("a b@example.com").is_err());
        assert!(validate_email("dev@example.com").is_ok());
        assert!(validate_otpauth("not base32 !!").is_err());
        assert!(validate_otpauth("otpauth://totp/x?algorithm=SHA256").is_err());
        assert!(
            validate_otpauth(
                "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30"
            )
            .is_ok()
        );
    }
}
