// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//
// Ported from dotnet/msbuild src/Tasks/ManifestUtil/mansign2.cs (MIT) for Sigilune.
// 変更点（Sigilune 側）:
//   - 署名の作成（Sign）だけを残し、検証は System.Deployment の実装（ClickOnce / VSTO の実行時と同じ）に任せる。
//   - 鍵は「SignHash だけを外部（Certum クラウド）へ委ねる RSA」を受け取る。秘密鍵の取り出しは一切しない。
//   - X509Data には、渡された中間証明書を明示的に入れる（ランナーの証明書ストアやオンライン取得に依存しない）。
//   - タイムスタンプは RFC 3161 のみ。旧式（clr.dll の CertTimestampAuthenticodeLicense）への切替はしない。
//   - SHA-1 署名は扱わない（Certum クラウドの署名 API が SHA-256 ダイジェスト前提のため）。

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Sigilune.Manifest
{
    /// <summary>Win32 / CLR の関数宣言（mansign2.cs の Win32 クラスから必要な分だけ移植）。</summary>
    internal static class Win32
    {
        private const string CRYPT32 = "crypt32.dll";
        private const string KERNEL32 = "kernel32.dll";
        // .NET Framework 4.x の実行時本体。公開鍵トークン・発行者鍵ハッシュは ClickOnce の検証側と同じ計算を使う。
        private const string MSCORWKS = "clr.dll";

        internal const int S_OK = 0;
        internal const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
        internal const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);

        internal const string szOID_NIST_sha256 = "2.16.840.1.101.3.4.2.1";

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct CRYPT_DATA_BLOB
        {
            internal uint cbData;
            internal IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_TIMESTAMP_CONTEXT
        {
            internal uint cbEncoded;
            internal IntPtr pbEncoded;
            internal IntPtr pTimeStamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPTOAPI_BLOB
        {
            internal uint cbData;
            internal IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_TIMESTAMP_PARA
        {
            internal IntPtr pszTSAPolicyId;
            internal bool fRequestCerts;
            internal CRYPTOAPI_BLOB Nonce;
            internal int cExtension;
            internal IntPtr rgExtension;
        }

        [DllImport(KERNEL32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr GetProcessHeap();

        [DllImport(KERNEL32, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool HeapFree([In] IntPtr hHeap, [In] uint dwFlags, [In] IntPtr lpMem);

        [DllImport(MSCORWKS, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int _AxlGetIssuerPublicKeyHash([In] IntPtr pCertContext, [In, Out] ref IntPtr ppwszPublicKeyHash);

        [DllImport(MSCORWKS, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern int _AxlPublicKeyBlobToPublicKeyToken([In] ref CRYPT_DATA_BLOB pCspPublicKeyBlob, [In, Out] ref IntPtr ppwszPublicKeyToken);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(CRYPT32, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptRetrieveTimeStamp(
            [In][MarshalAs(UnmanagedType.LPWStr)] string wszUrl,
            [In] uint dwRetrievalFlags,
            [In] int dwTimeout,
            [In][MarshalAs(UnmanagedType.LPStr)] string pszHashId,
            [In, Out] ref CRYPT_TIMESTAMP_PARA pPara,
            [In] byte[] pbData,
            [In] int cbData,
            [In, Out] ref IntPtr ppTsContext,
            [In, Out] ref IntPtr ppTsSigner,
            [In, Out] ref IntPtr phStore);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(CRYPT32, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        internal static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(CRYPT32, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        internal static extern bool CertCloseStore(IntPtr pCertContext, int dwFlags);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport(CRYPT32, CallingConvention = CallingConvention.Winapi)]
        internal static extern void CryptMemFree(IntPtr pv);
    }

    /// <summary>
    /// ClickOnce 用の SignedXml。署名時の Id 参照は KeyInfo だけを解決する（mansign2.cs と同じ）。
    /// </summary>
    internal sealed class ManifestSignedXml2 : SignedXml
    {
        internal const string Sha256SignatureMethodUri = "http://www.w3.org/2000/09/xmldsig#rsa-sha256";
        internal const string Sha256DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha256";

        internal ManifestSignedXml2(XmlElement elem) : base(elem) => RegisterAlgorithms();

        internal ManifestSignedXml2(XmlDocument document) : base(document) => RegisterAlgorithms();

        internal static void RegisterAlgorithms()
        {
            // ClickOnce は標準外の URI（2000/09/xmldsig#rsa-sha256, #sha256）を使うため、名前と実装を対応付ける。
            // .NET Framework の RSAPKCS1SHA256SignatureDescription は internal なので同等の型を自前で持つ。
            CryptoConfig.AddAlgorithm(typeof(RsaPkcs1Sha256SignatureDescription), Sha256SignatureMethodUri);
            CryptoConfig.AddAlgorithm(typeof(SHA256Cng), Sha256DigestMethod);
        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            KeyInfo keyInfo = KeyInfo;
            return keyInfo.Id != idValue ? null : keyInfo.GetXml();
        }
    }

    /// <summary>RSA PKCS#1 v1.5 + SHA-256 の XML 署名記述子。</summary>
    public sealed class RsaPkcs1Sha256SignatureDescription : SignatureDescription
    {
        public RsaPkcs1Sha256SignatureDescription()
        {
            KeyAlgorithm = typeof(RSA).AssemblyQualifiedName;
            DigestAlgorithm = typeof(SHA256Cng).AssemblyQualifiedName;
            FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).AssemblyQualifiedName;
            DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).AssemblyQualifiedName;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");
            return formatter;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter;
        }

        public override HashAlgorithm CreateDigest() => SHA256.Create();
    }

    /// <summary>マニフェスト署名者。鍵は SignHash を外部へ委ねる RSA、証明書は公開鍵だけを持つ。</summary>
    internal sealed class CmiManifestSigner2
    {
        internal CmiManifestSigner2(RSA strongNameKey, X509Certificate2 certificate)
        {
            StrongNameKey = strongNameKey ?? throw new ArgumentNullException(nameof(strongNameKey));
            Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        internal RSA StrongNameKey { get; }

        internal X509Certificate2 Certificate { get; }

        /// <summary>署名者証明書の発行者（中間 CA）など、X509Data に入れる追加の証明書。ルートは入れない。</summary>
        internal X509Certificate2Collection ExtraCertificates { get; } = new X509Certificate2Collection();

        internal string Description { get; set; }

        internal string DescriptionUrl { get; set; }
    }

    /// <summary>ClickOnce マニフェストの署名（SHA-256 固定）。mansign2.cs の SignedCmiManifest2.Sign の移植。</summary>
    internal sealed class SignedCmiManifest2
    {
        private const string AssemblyNamespaceUri = "urn:schemas-microsoft-com:asm.v1";
        private const string AssemblyV2NamespaceUri = "urn:schemas-microsoft-com:asm.v2";
        private const string MSRelNamespaceUri = "http://schemas.microsoft.com/windows/rel/2005/reldata";
        private const string LicenseNamespaceUri = "urn:mpeg:mpeg21:2003:01-REL-R-NS";
        private const string AuthenticodeNamespaceUri = "http://schemas.microsoft.com/windows/pki/2005/Authenticode";
        private const string licenseTemplate = "<r:license xmlns:r=\"" + LicenseNamespaceUri + "\" xmlns:as=\"" + AuthenticodeNamespaceUri + "\">" +
                                               "<r:grant>" +
                                               "<as:ManifestInformation>" +
                                               "<as:assemblyIdentity />" +
                                               "</as:ManifestInformation>" +
                                               "<as:SignedBy/>" +
                                               "<as:AuthenticodePublisher>" +
                                               "<as:X509SubjectName>CN=dummy</as:X509SubjectName>" +
                                               "</as:AuthenticodePublisher>" +
                                               "</r:grant><r:issuer></r:issuer></r:license>";

        private readonly XmlDocument _manifestDom;

        internal SignedCmiManifest2(XmlDocument manifestDom)
        {
            _manifestDom = manifestDom ?? throw new ArgumentNullException(nameof(manifestDom));
        }

        /// <summary>
        /// 署名する。timeStampUrl が null / 空ならタイムスタンプを付けない（検証用の比較テストのみで使う）。
        /// </summary>
        internal void Sign(CmiManifestSigner2 signer, string timeStampUrl)
        {
            RemoveExistingSignature(_manifestDom);
            ReplacePublicKeyToken(_manifestDom, signer.StrongNameKey);
            InsertPublisherIdentity(_manifestDom, signer.Certificate);
            XmlDocument licenseDom = CreateLicenseDom(signer, ExtractPrincipalFromManifest(), ComputeHashFromManifest(_manifestDom));
            AuthenticodeSignLicenseDom(licenseDom, signer, timeStampUrl);
            StrongNameSignManifestDom(_manifestDom, licenseDom, signer);
        }

        private XmlElement ExtractPrincipalFromManifest()
        {
            XmlNamespaceManager nsm = new XmlNamespaceManager(_manifestDom.NameTable);
            nsm.AddNamespace("asm", AssemblyNamespaceUri);
            if (!(_manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", nsm) is XmlElement assemblyIdentityNode))
            {
                throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
            }

            return assemblyIdentityNode;
        }

        private static void InsertPublisherIdentity(XmlDocument manifestDom, X509Certificate2 signerCert)
        {
            XmlNamespaceManager nsm = new XmlNamespaceManager(manifestDom.NameTable);
            nsm.AddNamespace("asm", AssemblyNamespaceUri);
            nsm.AddNamespace("asm2", AssemblyV2NamespaceUri);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            XmlElement assembly = manifestDom.SelectSingleNode("asm:assembly", nsm) as XmlElement;
            if (!(manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", nsm) is XmlElement))
            {
                throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
            }

            // 既存の要素があれば再利用する。
            XmlElement publisherIdentity = manifestDom.SelectSingleNode("asm:assembly/asm2:publisherIdentity", nsm) as XmlElement
                ?? manifestDom.CreateElement("publisherIdentity", AssemblyV2NamespaceUri);

            // 発行者の公開鍵ハッシュは ClickOnce の検証側と同じ CLR 関数で計算する。
            IntPtr pIssuerKeyHash = IntPtr.Zero;
            int hr = Win32._AxlGetIssuerPublicKeyHash(signerCert.Handle, ref pIssuerKeyHash);
            if (hr != Win32.S_OK)
            {
                throw new CryptographicException(hr);
            }

            string issuerKeyHash = Marshal.PtrToStringUni(pIssuerKeyHash);
            Win32.HeapFree(Win32.GetProcessHeap(), 0, pIssuerKeyHash);

            publisherIdentity.SetAttribute("name", signerCert.SubjectName.Name);
            publisherIdentity.SetAttribute("issuerKeyHash", issuerKeyHash);

            if (manifestDom.SelectSingleNode("asm:assembly/ds:Signature", nsm) is XmlElement signature)
            {
                assembly.InsertBefore(publisherIdentity, signature);
            }
            else
            {
                assembly.AppendChild(publisherIdentity);
            }
        }

        private static void RemoveExistingSignature(XmlDocument manifestDom)
        {
            XmlNamespaceManager nsm = new XmlNamespaceManager(manifestDom.NameTable);
            nsm.AddNamespace("asm", AssemblyNamespaceUri);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            XmlNode signatureNode = manifestDom.SelectSingleNode("asm:assembly/ds:Signature", nsm);
            signatureNode?.ParentNode.RemoveChild(signatureNode);
        }

        private static void ReplacePublicKeyToken(XmlDocument manifestDom, RSA snKey)
        {
            XmlNamespaceManager nsm = new XmlNamespaceManager(manifestDom.NameTable);
            nsm.AddNamespace("asm", AssemblyNamespaceUri);
            if (!(manifestDom.SelectSingleNode("asm:assembly/asm:assemblyIdentity", nsm) is XmlElement assemblyIdentity)
                || !assemblyIdentity.HasAttribute("publicKeyToken"))
            {
                throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
            }

            // 公開鍵だけを CSP 形式の blob にしてトークンを計算する（秘密鍵は使わない）。
            byte[] cspPublicKeyBlob;
            using (RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider())
            {
                rsaCsp.ImportParameters(snKey.ExportParameters(false));
                cspPublicKeyBlob = rsaCsp.ExportCspBlob(false);
            }

            unsafe
            {
                fixed (byte* pbPublicKeyBlob = cspPublicKeyBlob)
                {
                    Win32.CRYPT_DATA_BLOB publicKeyBlob = new Win32.CRYPT_DATA_BLOB
                    {
                        cbData = (uint)cspPublicKeyBlob.Length,
                        pbData = new IntPtr(pbPublicKeyBlob),
                    };
                    IntPtr pPublicKeyToken = IntPtr.Zero;

                    int hr = Win32._AxlPublicKeyBlobToPublicKeyToken(ref publicKeyBlob, ref pPublicKeyToken);
                    if (hr != Win32.S_OK)
                    {
                        throw new CryptographicException(hr);
                    }

                    string publicKeyToken = Marshal.PtrToStringUni(pPublicKeyToken);
                    Win32.HeapFree(Win32.GetProcessHeap(), 0, pPublicKeyToken);

                    assemblyIdentity.SetAttribute("publicKeyToken", publicKeyToken);
                }
            }
        }

        private static byte[] ComputeHashFromManifest(XmlDocument manifestDom)
        {
            // 渡された DOM は正規化済みとは限らないため読み直す。Fusion は空白を常に保持するので保持する。
            XmlDocument normalizedDom = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            using (TextReader stringReader = new StringReader(manifestDom.OuterXml))
            {
                XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null };
                using (XmlReader reader = XmlReader.Create(stringReader, settings, manifestDom.BaseURI))
                {
                    normalizedDom.Load(reader);
                }
            }

            XmlDsigExcC14NTransform exc = new XmlDsigExcC14NTransform();
            exc.LoadInput(normalizedDom);

            using (SHA256 sha2 = SHA256.Create())
            {
                byte[] hash = sha2.ComputeHash((MemoryStream)exc.GetOutput());
                return hash ?? throw new CryptographicException(Win32.TRUST_E_BAD_DIGEST);
            }
        }

        private static XmlDocument CreateLicenseDom(CmiManifestSigner2 signer, XmlElement principal, byte[] hash)
        {
            XmlDocument licenseDom = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
            using (StringReader sr = new StringReader(licenseTemplate))
            using (XmlReader reader = XmlReader.Create(sr, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = null }))
            {
                licenseDom.Load(reader);
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(licenseDom.NameTable);
            nsm.AddNamespace("r", LicenseNamespaceUri);
            nsm.AddNamespace("as", AuthenticodeNamespaceUri);
            XmlElement assemblyIdentityNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:grant/as:ManifestInformation/as:assemblyIdentity", nsm);
            assemblyIdentityNode.RemoveAllAttributes();
            foreach (XmlAttribute attribute in principal.Attributes)
            {
                assemblyIdentityNode.SetAttribute(attribute.Name, attribute.Value);
            }

            XmlElement manifestInformationNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:grant/as:ManifestInformation", nsm);
            manifestInformationNode.SetAttribute("Hash", hash.Length == 0 ? string.Empty : BytesToHexString(hash, 0, hash.Length));
            manifestInformationNode.SetAttribute("Description", signer.Description ?? string.Empty);
            manifestInformationNode.SetAttribute("Url", signer.DescriptionUrl ?? string.Empty);

            XmlElement authenticodePublisherNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:grant/as:AuthenticodePublisher/as:X509SubjectName", nsm);
            authenticodePublisherNode.InnerText = signer.Certificate.SubjectName.Name;

            return licenseDom;
        }

        private static void AuthenticodeSignLicenseDom(XmlDocument licenseDom, CmiManifestSigner2 signer, string timeStampUrl)
        {
            // Authenticode 側も同じ鍵（Certum の署名鍵）で署名する。
            RSA rsaPrivateKey = signer.StrongNameKey;

            ManifestSignedXml2 signedXml = new ManifestSignedXml2(licenseDom)
            {
                SigningKey = rsaPrivateKey,
            };
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = ManifestSignedXml2.Sha256SignatureMethodUri;

            // 鍵情報。X509Data は署名者証明書と中間証明書（ルートは含めない）。
            signedXml.KeyInfo.AddClause(new RSAKeyValue(rsaPrivateKey));
            signedXml.KeyInfo.AddClause(CreateX509Data(signer));

            Reference reference = new Reference
            {
                Uri = string.Empty,
                DigestMethod = ManifestSignedXml2.Sha256DigestMethod,
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(reference);

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            xmlDigitalSignature.SetAttribute("Id", "AuthenticodeSignature");

            XmlNamespaceManager nsm = new XmlNamespaceManager(licenseDom.NameTable);
            nsm.AddNamespace("r", LicenseNamespaceUri);
            XmlElement issuerNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:issuer", nsm);
            issuerNode.AppendChild(licenseDom.ImportNode(xmlDigitalSignature, true));

            if (!string.IsNullOrEmpty(timeStampUrl))
            {
                TimestampSignedLicenseDom(licenseDom, timeStampUrl);
            }

            licenseDom.DocumentElement.ParentNode.InnerXml = "<msrel:RelData xmlns:msrel=\"" +
                                                             MSRelNamespaceUri + "\">" +
                                                             licenseDom.OuterXml + "</msrel:RelData>";
        }

        /// <summary>
        /// 証明書チェーンの X509Data。中間証明書が渡されなければ mansign2.cs と同じく
        /// X509IncludeOption.ExcludeRoot でチェーンを組み立てる。
        /// </summary>
        private static KeyInfoX509Data CreateX509Data(CmiManifestSigner2 signer)
        {
            if (signer.ExtraCertificates.Count == 0)
            {
                return new KeyInfoX509Data(signer.Certificate, X509IncludeOption.ExcludeRoot);
            }

            KeyInfoX509Data data = new KeyInfoX509Data(signer.Certificate);
            foreach (X509Certificate2 extra in signer.ExtraCertificates)
            {
                data.AddCertificate(extra);
            }

            return data;
        }

        /// <summary>RFC 3161 タイムスタンプを取得する（mage.exe 由来の実装）。</summary>
        private static string ObtainRFC3161Timestamp(string timeStampUrl, string signatureValue)
        {
            byte[] sigValueBytes = Convert.FromBase64String(signatureValue);
            IntPtr ppTsContext = IntPtr.Zero;
            IntPtr ppTsSigner = IntPtr.Zero;
            IntPtr phStore = IntPtr.Zero;

            try
            {
                byte[] nonce = new byte[32];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(nonce);
                }

                // CryptEncodeObjectEx は nonce をリトルエンディアンの DER 整数として扱い、先頭バイトを落とすことがある。
                // 送った値と戻る値が食い違わないよう、最上位バイトを 0x01-0x7F に収める。
                nonce[nonce.Length - 1] &= 0x7f;
                nonce[nonce.Length - 1] |= 0x01;

                Win32.CRYPT_TIMESTAMP_PARA para = new Win32.CRYPT_TIMESTAMP_PARA
                {
                    fRequestCerts = true,
                    pszTSAPolicyId = IntPtr.Zero,
                };

                unsafe
                {
                    fixed (byte* pbNonce = nonce)
                    {
                        para.Nonce.cbData = (uint)nonce.Length;
                        para.Nonce.pbData = (IntPtr)pbNonce;

                        if (!Win32.CryptRetrieveTimeStamp(
                            timeStampUrl,
                            0,
                            60 * 1000,
                            Win32.szOID_NIST_sha256,
                            ref para,
                            sigValueBytes,
                            sigValueBytes.Length,
                            ref ppTsContext,
                            ref ppTsSigner,
                            ref phStore))
                        {
                            throw new CryptographicException(Marshal.GetLastWin32Error());
                        }
                    }
                }

                Win32.CRYPT_TIMESTAMP_CONTEXT timestampContext = (Win32.CRYPT_TIMESTAMP_CONTEXT)Marshal.PtrToStructure(ppTsContext, typeof(Win32.CRYPT_TIMESTAMP_CONTEXT));
                byte[] encodedBytes = new byte[(int)timestampContext.cbEncoded];
                Marshal.Copy(timestampContext.pbEncoded, encodedBytes, 0, (int)timestampContext.cbEncoded);
                return Convert.ToBase64String(encodedBytes);
            }
            finally
            {
                if (ppTsContext != IntPtr.Zero)
                {
                    Win32.CryptMemFree(ppTsContext);
                }

                if (ppTsSigner != IntPtr.Zero)
                {
                    Win32.CertFreeCertificateContext(ppTsSigner);
                }

                if (phStore != IntPtr.Zero)
                {
                    Win32.CertCloseStore(phStore, 0);
                }
            }
        }

        private static void TimestampSignedLicenseDom(XmlDocument licenseDom, string timeStampUrl)
        {
            XmlNamespaceManager nsm = new XmlNamespaceManager(licenseDom.NameTable);
            nsm.AddNamespace("r", LicenseNamespaceUri);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
            nsm.AddNamespace("as", AuthenticodeNamespaceUri);

            XmlElement signatureValueNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:issuer/ds:Signature/ds:SignatureValue", nsm);
            // 旧式タイムスタンプへは切り替えない。取得できなければ失敗として扱う（証明書の失効後も検証できるよう必須にする）。
            string timestamp = ObtainRFC3161Timestamp(timeStampUrl, signatureValueNode.InnerText);

            XmlElement asTimestamp = licenseDom.CreateElement("as", "Timestamp", AuthenticodeNamespaceUri);
            asTimestamp.InnerText = timestamp;

            XmlElement dsObject = licenseDom.CreateElement("Object", SignedXml.XmlDsigNamespaceUrl);
            dsObject.AppendChild(asTimestamp);

            XmlElement signatureNode = (XmlElement)licenseDom.SelectSingleNode("r:license/r:issuer/ds:Signature", nsm);
            signatureNode.AppendChild(dsObject);
        }

        private static void StrongNameSignManifestDom(XmlDocument manifestDom, XmlDocument licenseDom, CmiManifestSigner2 signer)
        {
            RSA snKey = signer.StrongNameKey;

            XmlNamespaceManager nsm = new XmlNamespaceManager(manifestDom.NameTable);
            nsm.AddNamespace("asm", AssemblyNamespaceUri);
            if (!(manifestDom.SelectSingleNode("asm:assembly", nsm) is XmlElement signatureParent))
            {
                throw new CryptographicException(Win32.TRUST_E_SUBJECT_FORM_UNKNOWN);
            }

            ManifestSignedXml2 signedXml = new ManifestSignedXml2(signatureParent)
            {
                SigningKey = snKey,
            };
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = ManifestSignedXml2.Sha256SignatureMethodUri;

            signedXml.KeyInfo.AddClause(new RSAKeyValue(snKey));
            if (licenseDom != null)
            {
                signedXml.KeyInfo.AddClause(new KeyInfoNode(licenseDom.DocumentElement));
            }

            signedXml.KeyInfo.Id = "StrongNameKeyInfo";

            Reference enveloped = new Reference
            {
                Uri = string.Empty,
                DigestMethod = ManifestSignedXml2.Sha256DigestMethod,
            };
            enveloped.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            enveloped.AddTransform(new XmlDsigExcC14NTransform());
            signedXml.AddReference(enveloped);

            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            xmlDigitalSignature.SetAttribute("Id", "StrongNameSignature");
            signatureParent.AppendChild(xmlDigitalSignature);
        }

        private static readonly char[] s_hexValues = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        /// <summary>
        /// mansign2.cs と同じく「末尾から」16 進化する（ライセンス内の Hash 属性はこの並びで比較される）。
        /// </summary>
        private static string BytesToHexString(byte[] array, int start, int end)
        {
            char[] hexOrder = new char[(end - start) * 2];
            int i = end;
            int j = 0;
            while (i-- > start)
            {
                int digit = (array[i] & 0xf0) >> 4;
                hexOrder[j++] = s_hexValues[digit];
                digit = array[i] & 0x0f;
                hexOrder[j++] = s_hexValues[digit];
            }

            return new string(hexOrder);
        }
    }
}
