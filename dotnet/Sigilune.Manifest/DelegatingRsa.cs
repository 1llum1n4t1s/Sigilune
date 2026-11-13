using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sigilune.Manifest
{
    /// <summary>SHA-256 ダイジェストへ RSA PKCS#1 v1.5 署名を返す署名元。</summary>
    internal interface IDigestSigner
    {
        byte[] SignSha256(byte[] digest);
    }

    /// <summary>
    /// 公開鍵だけを持ち、署名（SignHash）だけを外部へ委ねる RSA。
    /// SignedXml・RSAKeyValue・公開鍵トークン計算は公開鍵の取り出しと SignHash しか使わないため、
    /// 秘密鍵を手元に置かずに ClickOnce の署名処理へそのまま渡せる。
    /// </summary>
    internal sealed class DelegatingRsa : RSA
    {
        private readonly RSAParameters _publicKey;
        private readonly IDigestSigner _signer;

        internal DelegatingRsa(X509Certificate2 certificate, IDigestSigner signer)
        {
            _signer = signer ?? throw new ArgumentNullException(nameof(signer));
            using (RSA publicKey = certificate.GetRSAPublicKey() ?? throw new NotSupportedException("the signing certificate does not have an RSA public key"))
            {
                _publicKey = publicKey.ExportParameters(false);
                KeySizeValue = publicKey.KeySize;
            }

            LegalKeySizesValue = new[] { new KeySizes(KeySizeValue, KeySizeValue, 0) };
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
            {
                // 秘密鍵はクラウド HSM の外へ出ない。
                throw new CryptographicException("the private key stays in the Certum cloud and cannot be exported");
            }

            return _publicKey;
        }

        public override void ImportParameters(RSAParameters parameters) =>
            throw new NotSupportedException("the key is bound to the Certum cloud certificate");

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (padding != RSASignaturePadding.Pkcs1)
            {
                throw new CryptographicException("only RSA PKCS#1 v1.5 signatures are supported");
            }

            if (hashAlgorithm != HashAlgorithmName.SHA256 || hash == null || hash.Length != 32)
            {
                // Certum の署名 API は SHA-256 ダイジェスト前提。SHA-1 マニフェストは扱わない。
                throw new CryptographicException($"only SHA-256 digests are supported (got {hashAlgorithm.Name})");
            }

            byte[] signature = _signer.SignSha256(hash);
            // 返ってきた署名を公開鍵で確かめてから使う（誤った鍵・壊れた応答を署名に埋め込まない）。
            if (!VerifyHash(hash, signature, hashAlgorithm, padding))
            {
                throw new CryptographicException("the returned signature does not verify against the signing certificate");
            }

            return signature;
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            using (RSA verifier = RSA.Create())
            {
                verifier.ImportParameters(_publicKey);
                return verifier.VerifyHash(hash, signature, hashAlgorithm, padding);
            }
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            using (HashAlgorithm h = Create(hashAlgorithm))
            {
                return h.ComputeHash(data, offset, count);
            }
        }

        protected override byte[] HashData(System.IO.Stream data, HashAlgorithmName hashAlgorithm)
        {
            using (HashAlgorithm h = Create(hashAlgorithm))
            {
                return h.ComputeHash(data);
            }
        }

        private static HashAlgorithm Create(HashAlgorithmName name) =>
            name == HashAlgorithmName.SHA256 ? SHA256.Create() : throw new CryptographicException($"unsupported hash {name.Name}");

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) =>
            throw new NotSupportedException("decryption is not supported");

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) =>
            throw new NotSupportedException("encryption is not supported");

        public override byte[] DecryptValue(byte[] rgb) => throw new NotSupportedException();

        public override byte[] EncryptValue(byte[] rgb) => throw new NotSupportedException();
    }

    /// <summary>`sigilune sign-hash` を呼んで Certum クラウドで署名する。セッションは sigilune 側のキャッシュを使う。</summary>
    internal sealed class SigiluneProcessSigner : IDigestSigner
    {
        private readonly string _sigilune;

        internal SigiluneProcessSigner(string sigilunePath)
        {
            _sigilune = sigilunePath;
        }

        public byte[] SignSha256(byte[] digest)
        {
            string hex = BitConverter.ToString(digest).Replace("-", string.Empty).ToLowerInvariant();
            ProcessStartInfo psi = new ProcessStartInfo(_sigilune, "sign-hash --no-login " + hex)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.ASCII,
            };
            using (Process p = Process.Start(psi))
            {
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0)
                {
                    throw new CryptographicException($"sigilune sign-hash failed (exit {p.ExitCode}): {stderr.Trim()}");
                }

                return Convert.FromBase64String(stdout.Trim());
            }
        }
    }

    /// <summary>
    /// 検証専用: PFX の秘密鍵で署名する。mage.exe と同じ鍵で署名して出力を突き合わせる比較テストに使う。
    /// </summary>
    internal sealed class PfxSigner : IDigestSigner, IDisposable
    {
        private readonly RSA _key;

        internal PfxSigner(X509Certificate2 certificateWithKey)
        {
            _key = certificateWithKey.GetRSAPrivateKey() ?? throw new CryptographicException("the PFX has no RSA private key");
        }

        public byte[] SignSha256(byte[] digest) =>
            _key.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        public void Dispose() => _key.Dispose();
    }
}
