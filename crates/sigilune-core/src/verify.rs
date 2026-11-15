//! WinVerifyTrust で Authenticode 署名を検証し、署名者とタイムスタンプを取り出す。
//!
//! 「Windows が有効と判定する」ことに加え、署名者の共通名とタイムスタンプの有無を
//! 呼出し側で照合できるようにする。タイムスタンプがないと、証明書の期限切れ後に
//! 配布済みのファイルまで無効になるため、`sigilune` は既定でタイムスタンプを必須にする。

use crate::cert::Cert;
use crate::wide::wide;
use anyhow::Result;
use serde::Serialize;
use std::path::Path;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation;
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};

// WinVerifyTrust が返す HRESULT。値は Windows SDK の定義（windows-sys）を使い、
// 報告（`status: u32`）と突き合わせやすいよう符号なしで持つ。
/// 署名されていない（TRUST_E_NOSIGNATURE）。
const TRUST_E_NOSIGNATURE: u32 = Foundation::TRUST_E_NOSIGNATURE as u32;
/// 署名形式に対応していない（TRUST_E_SUBJECT_FORM_UNKNOWN）。
pub const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = Foundation::TRUST_E_SUBJECT_FORM_UNKNOWN as u32;
/// 署名値は正しいが、ルート証明書が信頼されていない（CERT_E_UNTRUSTEDROOT）。
pub const CERT_E_UNTRUSTEDROOT: u32 = Foundation::CERT_E_UNTRUSTEDROOT as u32;
/// ファイルの内容が署名時のダイジェストと一致しない（TRUST_E_BAD_DIGEST）。
const TRUST_E_BAD_DIGEST: u32 = Foundation::TRUST_E_BAD_DIGEST as u32;
/// 署名値が不正（NTE_BAD_SIGNATURE）。
const NTE_BAD_SIGNATURE: u32 = Foundation::NTE_BAD_SIGNATURE as u32;

/// 検証結果。
#[derive(Debug, Serialize)]
pub struct SignatureReport {
    pub path: String,
    /// WinVerifyTrust の HRESULT（0 = 有効）。
    pub status: u32,
    pub valid: bool,
    pub signed: bool,
    pub signer: Option<String>,
    pub signer_thumbprint: Option<String>,
    pub issuer: Option<String>,
    pub timestamped: bool,
    pub timestamp_authority: Option<String>,
}

impl SignatureReport {
    /// 人が読む状態名。
    pub fn status_text(&self) -> String {
        match self.status {
            0 => "Valid".into(),
            TRUST_E_NOSIGNATURE => "NotSigned".into(),
            TRUST_E_SUBJECT_FORM_UNKNOWN => "UnsupportedFormat".into(),
            CERT_E_UNTRUSTEDROOT => "UntrustedRoot (0x800B0109)".into(),
            TRUST_E_BAD_DIGEST => "HashMismatch (0x80096010)".into(),
            NTE_BAD_SIGNATURE => "BadSignature (0x80090006)".into(),
            s => format!("Invalid (0x{s:08X})"),
        }
    }
}

/// ファイルの署名を検証する（失効確認はオフライン既定で行わない）。
pub fn inspect(path: &Path) -> Result<SignatureReport> {
    let path_w = wide(path.as_os_str());
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path_w.as_ptr(),
        hFile: null_mut(),
        pgKnownSubject: null_mut(),
    };
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: 構造体は呼出し中有効。状態は必ず CLOSE で解放する。
    let hr = unsafe { WinVerifyTrust(null_mut(), &mut action, &mut data as *mut _ as _) } as u32;
    let mut report = SignatureReport {
        path: path.display().to_string(),
        status: hr,
        valid: hr == 0,
        signed: hr != TRUST_E_NOSIGNATURE && hr != TRUST_E_SUBJECT_FORM_UNKNOWN,
        signer: None,
        signer_thumbprint: None,
        issuer: None,
        timestamped: false,
        timestamp_authority: None,
    };
    unsafe {
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if !prov.is_null() {
            let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
            if !sgnr.is_null() {
                if (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let leaf = (*(*sgnr).pasCertChain).pCert;
                    if !leaf.is_null() {
                        let c = Cert::duplicate(leaf);
                        report.signer = Some(c.common_name());
                        report.signer_thumbprint = Some(c.thumbprint());
                        report.issuer = Some(c.issuer_common_name());
                    }
                }
                if (*sgnr).csCounterSigners > 0 {
                    report.timestamped = true;
                    let ts = WTHelperGetProvSignerFromChain(prov, 0, 1, 0);
                    if !ts.is_null() && (*ts).csCertChain > 0 && !(*ts).pasCertChain.is_null() {
                        let tsc = (*(*ts).pasCertChain).pCert;
                        if !tsc.is_null() {
                            report.timestamp_authority = Some(Cert::duplicate(tsc).common_name());
                        }
                    }
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(null_mut(), &mut action, &mut data as *mut _ as _);
    }
    Ok(report)
}
