using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace Sigilune.Manifest
{
    /// <summary>
    /// sigilune-manifest.exe の入口。通常は sigilune.exe の `sign-manifest` / `verify-manifest` から呼ばれる。
    /// 利用者向けの出力は英語（公開 OSS のため）、コメントは日本語。
    /// </summary>
    internal static class Program
    {
        private const string Usage =
@"sigilune-manifest: sign and verify ClickOnce / VSTO manifests (.manifest, .application, .vsto)

  sign   --cert <signer.der> [--intermediate <ca.der>]... (--sigilune <sigilune.exe> | --test-pfx <file.pfx>)
         [--timestamp-url <url> | --no-timestamp] [--description <text>] [--description-url <url>]
         [--application <app.manifest>] <manifest>...
      Signs --application first (if given), then refreshes each <manifest>'s reference to it
      (size, digest, publicKeyToken) before signing it.
  verify [--signer <CN>] [--allow-no-timestamp] [--no-revocation] [--allow-untrusted-chain] <manifest>...
      Verifies with the .NET Framework ClickOnce verifier (the one VSTO and ClickOnce use).
  update-reference <deployment-manifest> <application-manifest>
      Refreshes the deployment manifest's reference without signing.

Normally run through `sigilune sign-manifest` / `sigilune verify-manifest`.";

        private static int Main(string[] args)
        {
            // パスに日本語などを含んでも呼び出し元（sigilune.exe・PowerShell）で化けないよう UTF-8 で出す。
            Console.OutputEncoding = new System.Text.UTF8Encoding(false);
            try
            {
                if (args.Length == 0 || args[0] == "-h" || args[0] == "--help")
                {
                    Console.WriteLine(Usage);
                    return args.Length == 0 ? 2 : 0;
                }

                Queue<string> rest = new Queue<string>(args.Skip(1));
                switch (args[0])
                {
                    case "sign":
                        return Sign(rest);
                    case "verify":
                        return Verify(rest);
                    case "update-reference":
                        return UpdateReferenceCommand(rest);
                    default:
                        Console.Error.WriteLine($"sigilune-manifest: unknown command '{args[0]}'\n\n{Usage}");
                        return 2;
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"sigilune-manifest: {Describe(e)}");
                return 1;
            }
        }

        private static string Describe(Exception e)
        {
            while (e is TargetInvocationException && e.InnerException != null)
            {
                e = e.InnerException;
            }

            string hr = e.HResult != 0 ? $" (0x{e.HResult:X8})" : string.Empty;
            // 不具合の調査用: SIGILUNE_MANIFEST_DEBUG=1 でスタックトレースも出す。
            string trace = Environment.GetEnvironmentVariable("SIGILUNE_MANIFEST_DEBUG") == "1" ? Environment.NewLine + e : string.Empty;
            return e.Message.Trim() + hr + trace;
        }

        private static string Next(Queue<string> q, string option) =>
            q.Count > 0 ? q.Dequeue() : throw new ArgumentException($"{option} needs a value");

        // ---------------------------------------------------------------- sign

        private static int Sign(Queue<string> q)
        {
            string certPath = null, sigilune = null, testPfx = null, application = null;
            string timestampUrl = "http://time.certum.pl", description = null, descriptionUrl = null;
            List<string> intermediates = new List<string>();
            List<string> files = new List<string>();
            while (q.Count > 0)
            {
                string a = q.Dequeue();
                switch (a)
                {
                    case "--cert": certPath = Next(q, a); break;
                    case "--intermediate": intermediates.Add(Next(q, a)); break;
                    case "--sigilune": sigilune = Next(q, a); break;
                    case "--test-pfx": testPfx = Next(q, a); break;
                    case "--timestamp-url": timestampUrl = Next(q, a); break;
                    case "--no-timestamp": timestampUrl = null; break;
                    case "--description": description = Next(q, a); break;
                    case "--description-url": descriptionUrl = Next(q, a); break;
                    case "--application": application = Next(q, a); break;
                    default:
                        if (a.StartsWith("--", StringComparison.Ordinal))
                        {
                            throw new ArgumentException($"unknown option {a}");
                        }

                        files.Add(a);
                        break;
                }
            }

            if (files.Count == 0 && application == null)
            {
                throw new ArgumentException("no manifest to sign");
            }

            if ((sigilune == null) == (testPfx == null))
            {
                throw new ArgumentException("pass exactly one of --sigilune or --test-pfx");
            }

            X509Certificate2 certificate;
            IDigestSigner signer;
            PfxSigner pfxSigner = null;
            if (testPfx != null)
            {
                // 比較テスト専用。パスワードは引数に取らず環境変数で受け取る。
                string password = Environment.GetEnvironmentVariable("SIGILUNE_TEST_PFX_PASSWORD") ?? string.Empty;
                X509Certificate2 withKey = new X509Certificate2(testPfx, password, X509KeyStorageFlags.EphemeralKeySet);
                certificate = new X509Certificate2(withKey.RawData);
                signer = pfxSigner = new PfxSigner(withKey);
            }
            else
            {
                certificate = new X509Certificate2(File.ReadAllBytes(certPath ?? throw new ArgumentException("--cert is required with --sigilune")));
                signer = new SigiluneProcessSigner(sigilune);
            }

            try
            {
                using (DelegatingRsa key = new DelegatingRsa(certificate, signer))
                {
                    CmiManifestSigner2 manifestSigner = new CmiManifestSigner2(key, certificate)
                    {
                        Description = description,
                        DescriptionUrl = descriptionUrl,
                    };
                    foreach (string path in intermediates)
                    {
                        manifestSigner.ExtraCertificates.Add(new X509Certificate2(File.ReadAllBytes(path)));
                    }

                    if (application != null)
                    {
                        SignFile(application, manifestSigner, timestampUrl);
                    }

                    foreach (string file in files)
                    {
                        if (application != null)
                        {
                            UpdateReference(file, application);
                        }

                        SignFile(file, manifestSigner, timestampUrl);
                    }
                }
            }
            finally
            {
                pfxSigner?.Dispose();
            }

            return 0;
        }

        /// <summary>MSBuild の SecurityUtilities.SignFile と同じ読み書きで署名する（空白保持・宣言の符号化で保存）。</summary>
        private static void SignFile(string path, CmiManifestSigner2 signer, string timestampUrl)
        {
            XmlDocument doc = LoadManifest(path);
            new SignedCmiManifest2(doc).Sign(signer, timestampUrl);
            SaveManifest(doc, path);
            Console.WriteLine($"Signed {Path.GetFullPath(path)}");
        }

        /// <summary>
        /// 保存する（宣言どおり UTF-8 BOM 付き）。改行は読み込んだときの形をそのまま書き戻す（mage.exe と同じ）。
        /// </summary>
        private static void SaveManifest(XmlDocument doc, string path) => doc.Save(path);

        /// <summary>
        /// 読み込む。mage.exe と同じく改行を正規化しない読み込み（XmlTextReader）にして、署名以外の部分を
        /// 元のファイルと同じバイト列のまま保つ。署名値は正規化（Exc-C14N）後の内容で決まるため改行の形式には左右されない。
        /// </summary>
        private static XmlDocument LoadManifest(string path)
        {
            XmlDocument doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            using (XmlTextReader reader = new XmlTextReader(path) { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null })
            {
                doc.Load(reader);
            }

            return doc;
        }

        // ---------------------------------------------------------------- update-reference

        private static int UpdateReferenceCommand(Queue<string> q)
        {
            if (q.Count != 2)
            {
                throw new ArgumentException("usage: update-reference <deployment-manifest> <application-manifest>");
            }

            string deployment = q.Dequeue();
            UpdateReference(deployment, q.Dequeue());
            return 0;
        }

        /// <summary>
        /// 配置マニフェスト（.vsto / .application）が参照するアプリケーション マニフェストの
        /// サイズ・ダイジェスト・公開鍵トークンを、署名後のファイルに合わせて更新する。
        /// アプリケーション マニフェストを署名すると内容と publicKeyToken が変わるため、署名後・配置マニフェストの署名前に呼ぶ。
        /// </summary>
        private static void UpdateReference(string deploymentPath, string applicationPath)
        {
            XmlDocument doc = LoadManifest(deploymentPath);
            string appName = Path.GetFileName(applicationPath);
            List<XmlElement> refs = doc.SelectNodes("/*[local-name()='assembly']/*[local-name()='dependency']/*[local-name()='dependentAssembly']")
                .Cast<XmlElement>()
                .Where(e => string.Equals(LastSegment(e.GetAttribute("codebase")), appName, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (refs.Count != 1)
            {
                throw new InvalidOperationException($"{deploymentPath} has {refs.Count} references to {appName} (expected exactly 1)");
            }

            XmlElement reference = refs[0];
            byte[] content = File.ReadAllBytes(applicationPath);
            reference.SetAttribute("size", content.LongLength.ToString(System.Globalization.CultureInfo.InvariantCulture));

            XmlElement digestMethod = reference.SelectSingleNode("*[local-name()='hash']/*[local-name()='DigestMethod']") as XmlElement;
            XmlElement digestValue = reference.SelectSingleNode("*[local-name()='hash']/*[local-name()='DigestValue']") as XmlElement;
            if (digestMethod == null || digestValue == null)
            {
                throw new InvalidOperationException($"the reference to {appName} has no hash element");
            }

            string algorithm = digestMethod.GetAttribute("Algorithm");
            byte[] hash;
            if (algorithm.EndsWith("#sha256", StringComparison.Ordinal))
            {
                using (SHA256 h = SHA256.Create())
                {
                    hash = h.ComputeHash(content);
                }
            }
            else if (algorithm.EndsWith("#sha1", StringComparison.Ordinal))
            {
                using (SHA1 h = SHA1.Create())
                {
                    hash = h.ComputeHash(content);
                }
            }
            else
            {
                throw new InvalidOperationException($"unsupported digest algorithm {algorithm}");
            }

            digestValue.InnerText = Convert.ToBase64String(hash);

            // 参照側の assemblyIdentity を、署名で確定した公開鍵トークンに合わせる。他の識別属性は一致を確認する。
            XmlElement referencedIdentity = reference.SelectSingleNode("*[local-name()='assemblyIdentity']") as XmlElement;
            XmlElement appIdentity = LoadManifest(applicationPath).SelectSingleNode("/*[local-name()='assembly']/*[local-name()='assemblyIdentity']") as XmlElement;
            if (referencedIdentity == null || appIdentity == null)
            {
                throw new InvalidOperationException("assemblyIdentity is missing in the deployment reference or the application manifest");
            }

            foreach (string attribute in new[] { "name", "version", "language", "processorArchitecture", "type" })
            {
                if (referencedIdentity.GetAttribute(attribute) != appIdentity.GetAttribute(attribute))
                {
                    throw new InvalidOperationException($"the deployment reference and the application manifest differ in '{attribute}'");
                }
            }

            referencedIdentity.SetAttribute("publicKeyToken", appIdentity.GetAttribute("publicKeyToken"));
            SaveManifest(doc, deploymentPath);
            Console.WriteLine($"Updated the reference to {appName} in {Path.GetFullPath(deploymentPath)}");
        }

        private static string LastSegment(string codebase) =>
            codebase.Split('/', '\\').Last();

        // ---------------------------------------------------------------- verify

        private static int Verify(Queue<string> q)
        {
            string expectedSigner = null;
            bool allowNoTimestamp = false;
            bool allowUntrustedChain = false;
            bool noRevocation = false;
            List<string> files = new List<string>();
            while (q.Count > 0)
            {
                string a = q.Dequeue();
                switch (a)
                {
                    case "--signer": expectedSigner = Next(q, a); break;
                    case "--allow-no-timestamp": allowNoTimestamp = true; break;
                    case "--no-revocation": noRevocation = true; break;
                    // 自己署名のテスト証明書で署名した出力を確かめるとき専用。
                    case "--allow-untrusted-chain": allowUntrustedChain = true; break;
                    default:
                        if (a.StartsWith("--", StringComparison.Ordinal))
                        {
                            throw new ArgumentException($"unknown option {a}");
                        }

                        files.Add(a);
                        break;
                }
            }

            if (files.Count == 0)
            {
                throw new ArgumentException("no manifest to verify");
            }

            int failures = 0;
            foreach (string file in files)
            {
                List<string> problems = new List<string>();
                string signer = "-", timestamp = "none", trustedPublisher = "-";
                try
                {
                    ManifestVerification r = ManifestVerification.Run(file, noRevocation);
                    signer = r.SignerCommonName ?? "-";
                    if (!r.ChainTrusted && !allowUntrustedChain)
                    {
                        problems.Add($"the signer's certificate chain is not trusted ({r.ChainStatus})");
                    }

                    if (expectedSigner != null && r.SignerCommonName != expectedSigner)
                    {
                        problems.Add($"unexpected signer (want {expectedSigner})");
                    }

                    if (r.TimestampTime.HasValue)
                    {
                        timestamp = r.TimestampTime.Value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
                    }
                    else if (!allowNoTimestamp)
                    {
                        problems.Add("no timestamp");
                    }

                    // 信頼された発行元への登録は利用者側の設定なので合否には使わず、状況だけ示す。
                    trustedPublisher = r.InTrustedPublishers ? "yes" : "no";
                }
                catch (Exception e)
                {
                    problems.Add("signature is not valid: " + Describe(e));
                }

                if (problems.Count > 0)
                {
                    failures++;
                }

                Console.WriteLine($"{(problems.Count == 0 ? "OK  " : "FAIL")} {Path.GetFullPath(file)} - signer: {signer}, timestamp: {timestamp}, in Trusted Publishers: {trustedPublisher}");
                foreach (string p in problems)
                {
                    Console.WriteLine($"     {p}");
                }
            }

            if (failures > 0)
            {
                Console.Error.WriteLine($"sigilune-manifest: {failures} of {files.Count} manifest(s) failed verification");
                return 1;
            }

            return 0;
        }
    }
}
