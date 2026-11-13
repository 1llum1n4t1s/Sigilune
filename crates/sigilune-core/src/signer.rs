//! ダイジェスト署名のバックエンド。
//!
//! signtool の `/dlib` から渡される「署名対象ダイジェスト（SHA-256, 32バイト）」に
//! RSA PKCS#1 v1.5 署名を返す。署名バイト列は big-endian（PKCS#1 の表現そのまま）。

use crate::session::Session;
use anyhow::Result;

/// ダイジェスト署名器。
pub trait DigestSigner: Send + Sync {
    /// 署名者の証明書（DER）。
    fn certificate_der(&self) -> &[u8];
    /// SHA-256 ダイジェストに署名する。
    fn sign_sha256(&self, digest: &[u8; 32]) -> Result<Vec<u8>>;
}

impl DigestSigner for Session {
    fn certificate_der(&self) -> &[u8] {
        Session::certificate_der(self)
    }
    fn sign_sha256(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        Session::sign_sha256(self, digest)
    }
}

/// テスト専用: ローカルの RSA 秘密鍵（PKCS#8 PEM）で署名する。
///
/// クラウドへ接続せずに signtool との受け渡しを検証するためのもので、
/// dlib のメタデータで明示したときだけ使われる。
#[cfg(feature = "local-key")]
pub struct LocalKeySigner {
    key: rsa::RsaPrivateKey,
    cert_der: Vec<u8>,
}

#[cfg(feature = "local-key")]
impl LocalKeySigner {
    pub fn from_files(key_pem: &std::path::Path, cert: &std::path::Path) -> Result<Self> {
        use anyhow::Context;
        use rsa::pkcs8::DecodePrivateKey;
        let pem = std::fs::read_to_string(key_pem)
            .with_context(|| format!("reading {}", key_pem.display()))?;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
            .context("parsing the test private key (PKCS#8 PEM)")?;
        let raw = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
        let cert_der = crate::cert::Cert::from_der(&raw)?.der().to_vec();
        Ok(Self { key, cert_der })
    }
}

#[cfg(feature = "local-key")]
impl DigestSigner for LocalKeySigner {
    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }
    fn sign_sha256(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        use rsa::Pkcs1v15Sign;
        use rsa::sha2::Sha256;
        Ok(self.key.sign(Pkcs1v15Sign::new::<Sha256>(), digest)?)
    }
}
