//! DPAPI（CryptProtectData）で現在のユーザーだけが復号できる形に保護する。
//!
//! セッションキャッシュの OAuth トークンは約30分間署名できる権限を持つため、
//! 平文で保存しない。UI を出さない指定で呼び、対話を要求された場合は失敗させる。

use anyhow::{Result, bail};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::Zeroizing;

/// 用途を区別する追加エントロピー。他アプリの DPAPI データと取り違えないようにする。
const ENTROPY: &[u8] = b"Sigilune.Session.v1";

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// 平文を保護する。
pub(crate) fn protect(plain: &[u8]) -> Result<Vec<u8>> {
    let input = blob(plain);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: 入力 blob は呼出し中有効。出力は LocalFree で解放する。
    unsafe {
        if CryptProtectData(
            &input,
            null(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        ) == 0
        {
            bail!("CryptProtectData failed (0x{:08X})", GetLastError());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

/// 保護済みデータを復号する。復号結果はドロップ時に消去する。
pub(crate) fn unprotect(sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let input = blob(sealed);
    let entropy = blob(ENTROPY);
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // SAFETY: 同上。復号済みバッファは複製後に 0 埋めしてから解放する。
    unsafe {
        if CryptUnprotectData(
            &input,
            null_mut(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        ) == 0
        {
            bail!("CryptUnprotectData failed (0x{:08X})", GetLastError());
        }
        let slice = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
        let v = Zeroizing::new(slice.to_vec());
        slice.fill(0);
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let sealed = protect(b"secret token").unwrap();
        assert_ne!(sealed.as_slice(), b"secret token");
        assert_eq!(unprotect(&sealed).unwrap().as_slice(), b"secret token");
    }

    #[test]
    fn tampered_data_is_rejected() {
        let mut sealed = protect(b"secret token").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(unprotect(&sealed).is_err());
    }
}
