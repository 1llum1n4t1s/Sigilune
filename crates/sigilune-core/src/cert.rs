//! 証明書の補助（CryptoAPI の CERT_CONTEXT を所有する薄いラッパー）。
//!
//! 共通名・拇印・有効期限の取得と、発行者の照合を Windows 自身の実装で行い、
//! signtool / WinVerifyTrust と同じ解釈に揃える。

use anyhow::{Result, bail};
use windows_sys::Win32::Foundation::{FILETIME, GetLastError, SYSTEMTIME};
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, CERT_SHA1_HASH_PROP_ID,
    CertCompareCertificateName, CertCreateCertificateContext, CertDuplicateCertificateContext,
    CertFreeCertificateContext, CertGetCertificateContextProperty, CertGetNameStringW,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING, szOID_COMMON_NAME,
};
use windows_sys::Win32::System::Time::FileTimeToSystemTime;

pub(crate) const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

/// 所有権付きの証明書コンテキスト。ドロップで解放する。
pub struct Cert(*const CERT_CONTEXT);

// CERT_CONTEXT は参照カウント付きで、読み取り専用の利用はスレッド間で安全。
unsafe impl Send for Cert {}
unsafe impl Sync for Cert {}

impl Cert {
    /// DER（または PEM）から作る。
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let der = if der.starts_with(b"-----BEGIN") {
            ssign_core::authenticode::pem_to_der(der)?
        } else {
            der.to_vec()
        };
        // SAFETY: 入力は呼出し中有効。CryptoAPI が内部へ複製する。
        let p = unsafe { CertCreateCertificateContext(ENCODING, der.as_ptr(), der.len() as u32) };
        if p.is_null() {
            bail!("the certificate could not be decoded (0x{:08X})", unsafe {
                GetLastError()
            });
        }
        Ok(Self(p))
    }

    /// 既存コンテキストの参照を複製して所有する。
    ///
    /// # Safety
    /// `p` は有効な CERT_CONTEXT であること。
    pub unsafe fn duplicate(p: *const CERT_CONTEXT) -> Self {
        Self(unsafe { CertDuplicateCertificateContext(p) })
    }

    pub fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.0
    }

    /// 所有権を呼出し元へ渡す（呼出し元が CertFreeCertificateContext する）。
    pub fn into_raw(self) -> *const CERT_CONTEXT {
        let p = self.0;
        std::mem::forget(self);
        p
    }

    /// 証明書の DER。
    pub fn der(&self) -> &[u8] {
        // SAFETY: コンテキストが生きている間は有効。
        unsafe {
            std::slice::from_raw_parts((*self.0).pbCertEncoded, (*self.0).cbCertEncoded as usize)
        }
    }

    fn name_attr(&self, issuer: bool) -> String {
        let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
        let oid = szOID_COMMON_NAME as *const core::ffi::c_void;
        // SAFETY: 1回目で必要長を得てから取得する。
        unsafe {
            let n = CertGetNameStringW(
                self.0,
                CERT_NAME_ATTR_TYPE,
                flags,
                oid,
                std::ptr::null_mut(),
                0,
            );
            let mut buf = vec![0u16; n.max(1) as usize];
            CertGetNameStringW(self.0, CERT_NAME_ATTR_TYPE, flags, oid, buf.as_mut_ptr(), n);
            String::from_utf16_lossy(&buf[..(n.saturating_sub(1)) as usize])
        }
    }

    /// 主体の共通名（CN）。
    pub fn common_name(&self) -> String {
        self.name_attr(false)
    }

    /// 発行者の共通名（CN）。
    pub fn issuer_common_name(&self) -> String {
        self.name_attr(true)
    }

    /// SHA-1 拇印（大文字16進）。
    pub fn thumbprint(&self) -> String {
        let mut buf = [0u8; 20];
        let mut len = buf.len() as u32;
        // SAFETY: バッファ長を渡して取得する。
        let ok = unsafe {
            CertGetCertificateContextProperty(
                self.0,
                CERT_SHA1_HASH_PROP_ID,
                buf.as_mut_ptr() as _,
                &mut len,
            )
        };
        if ok == 0 {
            String::new()
        } else {
            hex_upper(&buf[..len as usize])
        }
    }

    /// 有効期限（UTC, "YYYY-MM-DD HH:MM:SS"）。
    pub fn not_after(&self) -> String {
        // SAFETY: pCertInfo はコンテキストが生きている間有効。
        unsafe { filetime_to_string(&(*(*self.0).pCertInfo).NotAfter) }
    }

    /// `self` の発行者が `issuer` の主体と一致するか。
    pub fn is_issued_by(&self, issuer: &Cert) -> bool {
        // SAFETY: 両コンテキストは有効。
        unsafe {
            CertCompareCertificateName(
                ENCODING,
                &(*(*self.0).pCertInfo).Issuer,
                &(*(*issuer.0).pCertInfo).Subject,
            ) != 0
        }
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: 所有しているコンテキストを1回だけ解放する。
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }
}

pub(crate) fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn filetime_to_string(ft: &FILETIME) -> String {
    let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // SAFETY: 出力先は有効なスタック変数。
    if unsafe { FileTimeToSystemTime(ft, &mut st) } == 0 {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

/// Certum が SimplySign のコード署名証明書を発行する中間 CA（通常版・EV 版）。
/// ssign-core（MIT）から同梱したもので、署名へ埋め込み、利用者側で中間証明書の取得に頼らずチェーンを完結させる。
const INTERMEDIATES_DER: &[&[u8]] = &[
    include_bytes!("../certs/ccsca2021.der"),
    include_bytes!("../certs/cevcsca2021.der"),
];

/// `leaf` を発行した同梱の中間証明書。
pub fn intermediate_for(leaf: &Cert) -> Option<Cert> {
    INTERMEDIATES_DER
        .iter()
        .filter_map(|d| Cert::from_der(d).ok())
        .find(|c| leaf.is_issued_by(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELFTEST: &[u8] = include_bytes!("../tests/fixtures/selftest_cert.der");

    #[test]
    fn reads_names_and_thumbprint() {
        let c = Cert::from_der(SELFTEST).unwrap();
        assert!(!c.common_name().is_empty());
        assert_eq!(c.thumbprint().len(), 40);
        assert!(!c.not_after().is_empty());
        // 自己署名なので自分自身が発行者。
        assert!(c.is_issued_by(&c));
    }

    #[test]
    fn intermediates_are_certum_and_not_issuers_of_selftest() {
        for d in INTERMEDIATES_DER {
            let c = Cert::from_der(d).unwrap();
            assert!(c.common_name().contains("Certum"), "{}", c.common_name());
        }
        assert!(intermediate_for(&Cert::from_der(SELFTEST).unwrap()).is_none());
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(Cert::from_der(b"not a certificate").is_err());
    }
}
