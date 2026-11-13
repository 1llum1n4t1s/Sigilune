using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Sigilune.Manifest
{
    /// <summary>
    /// .NET Framework の System.Deployment にある ClickOnce 検証（SignedCmiManifest2）の各段階を呼んで確かめる。
    ///
    /// SignedCmiManifest2.Verify は SHA-256 マニフェストで次の性質を持つため、そのままでは合否に使えない。
    ///   - 成功しても AuthenticodeSignerInfo.ErrorCode が初期値 TRUST_E_FAIL のまま残り、タイムスタンプも記録しない。
    ///   - 最後に「署名者証明書が現在のユーザーの『信頼された発行元』ストアにあること」を要求する。
    ///     これは署名の正しさではなく利用者側の信頼設定で、CI のランナーや配布元の PC では満たされない。
    /// そこで、実行時と同じ内部処理（強名署名・識別情報・Authenticode 署名・タイムスタンプ・発行者情報）を
    /// 同じ順序で呼び、証明書チェーンも実行時と同じ条件で組み立てる。省くのは『信頼された発行元』の確認だけで、
    /// その有無は結果に記録する。内部型のため反射で呼ぶ（.NET Framework 4.8 の実装に合わせている）。
    /// </summary>
    internal sealed class ManifestVerification
    {
        private const BindingFlags Any = BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
        private const int TRUST_E_FAIL = unchecked((int)0x800B010B);
        private const int CmiVerifyRevocationNoCheck = 0x1;
        private const int CmiVerifyLifetimeSigning = 0x10;
        private const int CmiVerifyStrongNameOnly = 0x10000;

        internal string SignerCommonName { get; private set; }

        internal string ChainStatus { get; private set; }

        internal bool ChainTrusted { get; private set; }

        internal DateTime? TimestampTime { get; private set; }

        /// <summary>署名者証明書が現在のユーザーの『信頼された発行元』にあるか（情報のみ）。</summary>
        internal bool InTrustedPublishers { get; private set; }

        internal static ManifestVerification Run(string path, bool noRevocation)
        {
            Assembly deployment = typeof(System.Deployment.Application.ApplicationDeployment).Assembly;
            Type manifestType = deployment.GetType("System.Deployment.Internal.CodeSigning.SignedCmiManifest2", true);
            Type flagsType = deployment.GetType("System.Deployment.Internal.CodeSigning.CmiManifestVerifyFlags", true);
            Type hashAlgType = deployment.GetType("System.Deployment.Internal.CodeSigning.SupportedHashAlgorithm", true);
            Type signedXmlType = deployment.GetType("System.Deployment.Internal.CodeSigning.ManifestSignedXml2", true);
            Type signerInfoType = deployment.GetType("System.Deployment.Internal.CodeSigning.CmiAuthenticodeSignerInfo", true);

            XmlDocument doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            using (XmlReader reader = XmlReader.Create(path, new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null }))
            {
                doc.Load(reader);
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(doc.NameTable);
            nsm.AddNamespace("asm", "urn:schemas-microsoft-com:asm.v1");
            nsm.AddNamespace("asm2", "urn:schemas-microsoft-com:asm.v2");
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            nsm.AddNamespace("msrel", "http://schemas.microsoft.com/windows/rel/2005/reldata");
            nsm.AddNamespace("r", "urn:mpeg:mpeg21:2003:01-REL-R-NS");
            nsm.AddNamespace("as", "http://schemas.microsoft.com/windows/pki/2005/Authenticode");

            string method = (doc.SelectSingleNode("/*/ds:Signature/ds:SignedInfo/ds:SignatureMethod", nsm) as XmlElement)?.GetAttribute("Algorithm") ?? string.Empty;
            if (!method.EndsWith("rsa-sha256", StringComparison.Ordinal))
            {
                throw new CryptographicException($"only rsa-sha256 manifests are supported (signature method: {method})");
            }

            // ClickOnce の実行時と同じく、標準外の SHA-256 URI を検証前に登録する。
            ManifestSignedXml2.RegisterAlgorithms();
            object manifest = Activator.CreateInstance(manifestType, Any, null, new object[] { doc, true }, null);
            object sha256 = Enum.Parse(hashAlgType, "SHA256");

            // 1) 強名署名と公開鍵トークン（実行時の Verify を StrongNameOnly で呼ぶ）。
            int revocation = noRevocation ? CmiVerifyRevocationNoCheck : 0;
            Invoke(manifestType, manifest, "Verify", Enum.ToObject(flagsType, CmiVerifyStrongNameOnly | revocation));

            // 2) Authenticode（発行者）署名。以下は実行時の VerifyLicenseNew と同じ順序。
            if (!(doc.SelectSingleNode("asm:assembly/ds:Signature/ds:KeyInfo/msrel:RelData/r:license", nsm) is XmlElement license))
            {
                throw new CryptographicException("the manifest has no Authenticode (publisher) signature");
            }

            Invoke(manifestType, manifest, "VerifyAssemblyIdentity", nsm, sha256);
            // 内部処理が失敗時に ErrorCode を書き込むため、実行時と同じ初期値の情報を置いておく。
            manifestType.GetField("m_authenticodeSignerInfo", Any)
                .SetValue(manifest, Activator.CreateInstance(signerInfoType, Any, null, new object[] { TRUST_E_FAIL }, null));

            XmlElement signatureNode = license.SelectSingleNode("//r:issuer/ds:Signature", nsm) as XmlElement
                ?? throw new CryptographicException("the publisher signature element is missing");
            Invoke(manifestType, manifest, "VerifySignatureForm", signatureNode, "AuthenticodeSignature", nsm);

            XmlDocument licenseDoc = new XmlDocument { XmlResolver = null };
            licenseDoc.LoadXml(license.OuterXml);
            XmlElement licenseSignature = (XmlElement)licenseDoc.SelectSingleNode("//r:issuer/ds:Signature", nsm);
            SignedXml signedXml = (SignedXml)Activator.CreateInstance(signedXmlType, Any, null, new object[] { licenseDoc }, null);
            signedXml.LoadXml(licenseSignature);
            if (!signedXml.CheckSignature())
            {
                throw new CryptographicException("the publisher (Authenticode) signature does not verify");
            }

            object[] certArgs = { signedXml, nsm, null };
            X509Certificate2 signingCertificate = (X509Certificate2)Invoke(manifestType, manifest, "GetSigningCertificate", certArgs);
            X509Certificate2Collection intermediates = (X509Certificate2Collection)certArgs[2] ?? new X509Certificate2Collection();

            using (X509Store disallowed = new X509Store(StoreName.Disallowed, StoreLocation.CurrentUser))
            {
                disallowed.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                if (disallowed.Certificates.Contains(signingCertificate))
                {
                    throw new CryptographicException("the signing certificate is in the Untrusted Certificates (Disallowed) store");
                }
            }

            object[] infoArgs = { license, nsm, null, null, null };
            if (!(bool)Invoke(manifestType, manifest, "GetManifestInformation", infoArgs))
            {
                throw new CryptographicException("the publisher signature has no ManifestInformation");
            }

            object[] tsArgs = { licenseSignature, nsm, null };
            bool timestamped = (bool)Invoke(manifestType, manifest, "VerifySignatureTimestampNew", tsArgs);
            DateTime verificationTime = (DateTime)tsArgs[2];
            bool lifetimeSigning = timestamped && (bool)Invoke(manifestType, manifest, "GetLifetimeSigning", signingCertificate);

            // 実行時と同じ条件でチェーンを組む（コード署名 EKU、タイムスタンプ時刻、失効確認）。
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.RevocationMode = noRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
            chain.ChainPolicy.VerificationTime = verificationTime;
            if (timestamped && lifetimeSigning)
            {
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.4.1.311.10.3.13"));
            }

            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromMinutes(1);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.ExtraStore.AddRange(intermediates);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.3"));

            ManifestVerification r = new ManifestVerification
            {
                ChainTrusted = chain.Build(signingCertificate),
                ChainStatus = string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()).Distinct()),
                SignerCommonName = signingCertificate.GetNameInfo(X509NameType.SimpleName, false),
                TimestampTime = timestamped ? verificationTime : (DateTime?)null,
            };

            if (!(license.SelectSingleNode("r:grant/as:AuthenticodePublisher/as:X509SubjectName", nsm) is XmlElement subject)
                || !string.Equals(signingCertificate.Subject, subject.InnerText, StringComparison.Ordinal))
            {
                throw new CryptographicException("the publisher name in the signature does not match the signing certificate");
            }

            // 実行時と同じく、組み立てたチェーンを署名者情報へ渡してから発行者情報（名前・発行者鍵ハッシュ）を照合する。
            object signerInfo = manifestType.GetField("m_authenticodeSignerInfo", Any).GetValue(manifest);
            signerInfoType.GetProperty("SignerChain", Any).SetValue(signerInfo, chain);
            Invoke(manifestType, manifest, "VerifyPublisherIdentity", nsm);

            using (X509Store trusted = new X509Store(StoreName.TrustedPublisher, StoreLocation.CurrentUser))
            {
                trusted.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                r.InTrustedPublishers = trusted.Certificates.Contains(signingCertificate);
            }

            return r;
        }

        /// <summary>内部メソッドを呼ぶ。out 引数は args 配列に書き戻される。例外は中身を取り出して投げ直す。</summary>
        private static object Invoke(Type type, object target, string name, params object[] args)
        {
            MethodInfo m = type.GetMethods(Any).SingleOrDefault(x => x.Name == name && x.GetParameters().Length == args.Length)
                ?? throw new MissingMethodException(type.FullName, name);
            try
            {
                return m.Invoke(target, args);
            }
            catch (TargetInvocationException e) when (e.InnerException is CryptographicException ce)
            {
                // 実行時の検証が不合格と判断した（HRESULT を保ったまま投げ直す）。
                throw new CryptographicException($"{name}: {ce.Message.Trim()}", ce);
            }
            catch (TargetInvocationException e) when (e.InnerException != null)
            {
                // 内部実装の想定外の失敗。どの段階かを分かるようにする。
                throw new InvalidOperationException($"{name} failed: {e.InnerException.Message.Trim()}", e.InnerException);
            }
        }
    }
}
