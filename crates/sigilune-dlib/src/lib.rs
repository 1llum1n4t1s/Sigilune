//! signtool `/dlib` 用のダイジェスト署名 DLL。
//!
//! signtool（SignerSignEx3）は、ファイル形式ごとの署名データを自分で組み立て、
//! 署名すべきダイジェストだけをこの DLL の `AuthenticodeDigestSignEx` へ渡す。
//! ここで Certum クラウドの鍵に署名させ、署名者証明書と中間証明書を返す。
//!
//! # 契約（Microsoft Learn: PFN_AUTHENTICODE_DIGEST_SIGN_EX）
//! - `pSignedDigest->pbData` は `HeapAlloc(GetProcessHeap(), ...)` で確保する（解放は呼出し元）。
//! - `*ppSignerCert` は呼出し元が `CertFreeCertificateContext` で解放する。
//! - `hCertChainStore` は任意。渡されたら中間証明書を追加し、署名にチェーンを埋め込ませる。
//!
//! # メタデータ（`/dmdf <json>`、任意）
//! - 省略時: Sigilune のセッション（キャッシュ→なければ資格情報で1回ログイン）で署名する。
//! - `{"local_key_pem": "...", "local_cert": "..."}`: テスト専用。ローカル鍵で署名する。
//!
//! パニックは FFI 境界を越えさせず、E_FAIL として返す。失敗理由は signtool のコンソールへ出す。

#![cfg(windows)]

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sigilune_core::cert::{Cert, intermediate_for};
use sigilune_core::session::{self, LoginPolicy};
use sigilune_core::signer::{DigestSigner, LocalKeySigner};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{
    E_FAIL, E_INVALIDARG, E_OUTOFMEMORY, HANDLE, NTE_BAD_ALGID, S_OK,
};
use windows_sys::Win32::Security::Cryptography::{
    CALG_SHA_256, CERT_CONTEXT, CERT_STORE_ADD_USE_EXISTING, CRYPT_INTEGER_BLOB,
    CertAddCertificateContextToStore, HCERTSTORE,
};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapAlloc};
use windows_sys::core::HRESULT;

/// dlib へのメタデータ。
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Metadata {
    local_key_pem: Option<std::path::PathBuf>,
    local_cert: Option<std::path::PathBuf>,
}

/// signtool は複数ファイルを1プロセスで署名するため、プロセス内で署名器を使い回す。
static SIGNER: Mutex<Option<Arc<dyn DigestSigner>>> = Mutex::new(None);

fn signer(meta: &Metadata) -> Result<Arc<dyn DigestSigner>> {
    let mut guard = SIGNER
        .lock()
        .map_err(|_| anyhow::anyhow!("signer lock poisoned"))?;
    if let Some(s) = guard.as_ref() {
        return Ok(s.clone());
    }
    let s: Arc<dyn DigestSigner> = match (&meta.local_key_pem, &meta.local_cert) {
        (Some(k), Some(c)) => Arc::new(LocalKeySigner::from_files(k, c)?),
        (None, None) => Arc::new(session::acquire(LoginPolicy::AllowLogin)?),
        _ => bail!("local_key_pem and local_cert must be given together"),
    };
    *guard = Some(s.clone());
    Ok(s)
}

unsafe fn parse_metadata(blob: *const CRYPT_INTEGER_BLOB) -> Result<Metadata> {
    if blob.is_null() || unsafe { (*blob).cbData } == 0 || unsafe { (*blob).pbData }.is_null() {
        return Ok(Metadata::default());
    }
    let bytes = unsafe { std::slice::from_raw_parts((*blob).pbData, (*blob).cbData as usize) };
    // signtool はファイル内容をそのまま渡す。UTF-8 BOM と末尾の NUL を許容する。
    let text = String::from_utf8_lossy(bytes);
    let text = text
        .trim_start_matches('\u{feff}')
        .trim_end_matches('\0')
        .trim();
    if text.is_empty() {
        return Ok(Metadata::default());
    }
    serde_json::from_str(text).context("the /dmdf metadata is not valid Sigilune JSON")
}

struct Failure(HRESULT, anyhow::Error);

unsafe fn sign_impl(
    metadata: *const CRYPT_INTEGER_BLOB,
    alg: u32,
    digest_ptr: *const u8,
    digest_len: u32,
    out: *mut CRYPT_INTEGER_BLOB,
    out_cert: *mut *const CERT_CONTEXT,
    chain_store: HCERTSTORE,
) -> std::result::Result<(), Failure> {
    if out.is_null() || out_cert.is_null() || digest_ptr.is_null() {
        return Err(Failure(
            E_INVALIDARG,
            anyhow::anyhow!("signtool passed a null pointer"),
        ));
    }
    // クラウドは SHA-256 の生ダイジェストにしか署名しない。
    if alg != CALG_SHA_256 || digest_len != 32 {
        return Err(Failure(
            NTE_BAD_ALGID,
            anyhow::anyhow!(
                "only SHA-256 is supported (use signtool /fd SHA256); got ALG_ID 0x{alg:X}, {digest_len} bytes"
            ),
        ));
    }
    let meta = unsafe { parse_metadata(metadata) }.map_err(|e| Failure(E_INVALIDARG, e))?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(unsafe { std::slice::from_raw_parts(digest_ptr, 32) });

    let s = signer(&meta).map_err(|e| Failure(E_FAIL, e))?;
    let leaf = Cert::from_der(s.certificate_der()).map_err(|e| Failure(E_FAIL, e))?;
    let signature = s.sign_sha256(&digest).map_err(|e| Failure(E_FAIL, e))?;

    // 中間証明書をチェーン用ストアへ追加する（見つからなければ signtool の通常のチェーン構築に任せる）。
    if !chain_store.is_null()
        && let Some(inter) = intermediate_for(&leaf)
    {
        unsafe {
            CertAddCertificateContextToStore(
                chain_store,
                inter.as_ptr(),
                CERT_STORE_ADD_USE_EXISTING,
                std::ptr::null_mut(),
            )
        };
    }

    // 署名は呼出し元が解放するプロセスヒープへ置く。
    let buf = unsafe { HeapAlloc(GetProcessHeap(), 0, signature.len()) } as *mut u8;
    if buf.is_null() {
        return Err(Failure(E_OUTOFMEMORY, anyhow::anyhow!("HeapAlloc failed")));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(signature.as_ptr(), buf, signature.len());
        (*out).cbData = signature.len() as u32;
        (*out).pbData = buf;
        *out_cert = leaf.into_raw();
    }
    Ok(())
}

unsafe fn guarded(f: impl FnOnce() -> std::result::Result<(), Failure>) -> HRESULT {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => S_OK,
        Ok(Err(Failure(hr, e))) => {
            eprintln!("sigilune-dlib: {e:#}");
            hr
        }
        Err(_) => {
            eprintln!("sigilune-dlib: internal error (panic)");
            E_FAIL
        }
    }
}

/// PFN_AUTHENTICODE_DIGEST_SIGN_EX。
///
/// # Safety
/// signtool（SignerSignEx3）から契約どおりの引数で呼ばれること。
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AuthenticodeDigestSignEx(
    metadata: *const CRYPT_INTEGER_BLOB,
    digest_alg: u32,
    digest: *const u8,
    digest_len: u32,
    signed_digest: *mut CRYPT_INTEGER_BLOB,
    signer_cert: *mut *const CERT_CONTEXT,
    chain_store: HCERTSTORE,
) -> HRESULT {
    unsafe {
        guarded(|| {
            sign_impl(
                metadata,
                digest_alg,
                digest,
                digest_len,
                signed_digest,
                signer_cert,
                chain_store,
            )
        })
    }
}

/// PFN_AUTHENTICODE_DIGEST_SIGN_EX_WITHFILEHANDLE。ファイルハンドルは使わない。
///
/// # Safety
/// 同上。
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AuthenticodeDigestSignExWithFileHandle(
    metadata: *const CRYPT_INTEGER_BLOB,
    digest_alg: u32,
    digest: *const u8,
    digest_len: u32,
    signed_digest: *mut CRYPT_INTEGER_BLOB,
    signer_cert: *mut *const CERT_CONTEXT,
    chain_store: HCERTSTORE,
    _file: HANDLE,
) -> HRESULT {
    unsafe {
        guarded(|| {
            sign_impl(
                metadata,
                digest_alg,
                digest,
                digest_len,
                signed_digest,
                signer_cert,
                chain_store,
            )
        })
    }
}
