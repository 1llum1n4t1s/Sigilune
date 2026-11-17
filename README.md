# Sigilune

Authenticode-sign **any format `signtool` supports** (verified so far: `.exe`, `.msi`, `.msix`, `.ps1`; `.dll`, `.appx`, `.cab`, `.cat`, … go through the same signtool path) with a **Certum SimplySign cloud code-signing certificate**, without SimplySign Desktop and without typing a one-time code.

```powershell
sigilune setup --email you@example.com      # once: stores the TOTP seed in Windows Credential Manager
sigilune sign .\dist\MyApp.exe .\dist\MyApp.msix
```

```
Successfully signed: D:\dist\MyApp.exe
Successfully signed: D:\dist\MyApp.msix
OK   D:\dist\MyApp.exe — Valid, signer: Open Source Developer Jane Doe, timestamp: Certum Timestamp 2026
OK   D:\dist\MyApp.msix — Valid, signer: Open Source Developer Jane Doe, timestamp: Certum Timestamp 2026
```

## How it works

```
sigilune sign ──► signtool sign /fd SHA256 /tr http://time.certum.pl /td SHA256 /dlib sigilune_dlib.dll <files>
                      │  (signtool + Windows SIPs build the format-specific signature)
                      ▼
                 sigilune_dlib.dll  AuthenticodeDigestSignEx(digest)
                      │
                      ▼
                 Certum SimplySign cloud HSM  (HTTPS, via ssign-core)
```

- **All formats:** Sigilune implements signtool's *digest signing library* interface (`/dlib`, the same mechanism Azure Trusted Signing uses). signtool builds the signature for each format and Sigilune only signs the digest in the cloud, so anything signtool can sign works, including MSIX.
- **No SimplySign Desktop:** the cloud protocol is spoken directly over HTTPS by [`ssign-core`](https://github.com/Le-Syl21/ssign).
- **No secrets on the command line:** the account e-mail and TOTP seed live in Windows Credential Manager. The OAuth token (valid ~30 min) is cached encrypted with DPAPI for the current user only.
- **Parallel-safe:** logins are serialized with a named mutex and the session is shared across processes, so build tools that sign one file per process (Velopack, electron-builder, …) log in once. A TOTP time window is never reused, and a failed login is never retried automatically.
- **Verified output:** after signing, every file is checked with `WinVerifyTrust`: the signature must be valid, the signer must match the session certificate, and an RFC 3161 timestamp must be present. The Certum intermediate CA is embedded so the chain is complete.

## Requirements

- Windows 10 2004 / Windows Server 2022 or later (x64)
- Windows SDK (`signtool.exe`). Set `SIGILUNE_SIGNTOOL` to use a specific one.
- A Certum SimplySign cloud code-signing certificate, and its **TOTP seed** (`otpauth://` URI). The seed is in the QR code shown when you register the SimplySign mobile token. Keep it as secret as a private key: anyone with the seed and your e-mail can sign as you.

## Quick start

**1. Install** (PowerShell, no admin rights needed):

```powershell
irm https://raw.githubusercontent.com/1llum1n4t1s/Sigilune/main/install.ps1 | iex
```

The installer downloads the latest release from `https://sigilune.kagayoi.com` (no GitHub Releases are used), checks its SHA-256 and the Authenticode signature of every binary, installs them to `%LOCALAPPDATA%\Programs\Sigilune` and adds that folder to your user `PATH`. Options: `-Version 1.0.0`, `-InstallDir <dir>`, `-NoPath`. To pass options, download the script first: `irm .../install.ps1 -OutFile install.ps1; .\install.ps1 -Version 1.0.0`.

**2. Register your account** (once per PC). You are asked for the `otpauth://` URI without echo:

```powershell
sigilune setup --email you@example.com
sigilune login
```

**3. Sign**:

```powershell
sigilune sign .\MyApp.exe
```

### Other ways to install

- **Manual**: download `https://sigilune.kagayoi.com/<version>/sigilune-<version>-win-x64.zip` (the newest version is in `https://sigilune.kagayoi.com/latest.json`), check it against the `.sha256` file next to it, and keep all files of the zip together in one folder.
- **From source**: `cargo build --release` → `target\release\sigilune.exe` and `target\release\sigilune_dlib.dll`; `dotnet build dotnet/Sigilune.Manifest -c Release` → `sigilune-manifest.exe` (+ `.config`), only needed for ClickOnce / VSTO manifests.

## GitHub Actions

Use the bundled action on a Windows runner. Put the two secrets in an **Environment limited to your release branches** (Settings → Environments → Deployment branches and tags) and reference it from the signing job. Adding required reviewers makes every run wait for your approval; leave them out if releases should finish unattended:

```yaml
jobs:
  release:
    runs-on: windows-latest
    environment: release          # holds SIGILUNE_EMAIL and SIGILUNE_TOTP_URI
    steps:
      - uses: actions/checkout@v7
      # ... build ...
      - uses: 1llum1n4t1s/Sigilune@<full commit SHA>   # 1.1.4
      - run: sigilune sign dist\MyApp.exe dist\MyApp.msix
        env:
          SIGILUNE_EMAIL: ${{ secrets.SIGILUNE_EMAIL }}
          SIGILUNE_TOTP_URI: ${{ secrets.SIGILUNE_TOTP_URI }}
```

Sign everything in **one job**. Parallel jobs on different machines would send the same 30-second TOTP code, and Certum rejects the second one. Never expose the secrets to `pull_request` workflows from forks.

Which binary the action installs:

| `uses:` | Installs |
| --- | --- |
| `1llum1n4t1s/Sigilune@<full commit SHA>` | The version written in `Cargo.toml` at that commit, so the SHA pins the version (there are no release tags; Dependabot can bump the SHA) |
| `with: version: 1.2.3` | That version, whatever the action ref |
| `with: version: latest` | The newest version in `latest.json` (not reproducible) |

## Updating

- **Your PC**: run the install command again. It replaces the binaries in place and keeps your registration (Credential Manager) and settings. `sigilune --version` shows the installed version.
- **GitHub Actions**: the commit SHA in `uses:` decides the version. Bump the SHA to update (Dependabot's `github-actions` updater does this for you). The SHA you pin must be a commit of a version that has been published.

## Commands

| Command | What it does |
| --- | --- |
| `sigilune setup --email <e-mail>` | Store the registration. The `otpauth://` URI (or Base32 seed) is read from a hidden prompt, or from stdin when piped. `--from-json <file> --email-pointer <ptr> --uri-pointer <ptr>` imports from a JSON secrets file. |
| `sigilune login` | Log in now (reuses a valid cached session). |
| `sigilune status` | Show the registration and cached session without contacting Certum. |
| `sigilune sign <files…>` | Sign with signtool + the dlib, then verify. Refuses already-signed files unless `--replace` (overwrite) or `--skip-signed` (leave files with a valid, trusted signature untouched; invalid signatures are still refused). Nested signatures are not supported yet. Also `--timestamp-url`, `--description`, `--description-url`, `--no-login`, `--json`. |
| `sigilune verify <files…>` | Verify validity and timestamp; `--signer <CN>` requires a signer; `--allow-no-timestamp`; `--json`. |
| `sigilune sign-manifest <manifests…>` | Sign ClickOnce / VSTO manifests (`.manifest`, `.application`, `.vsto`), then verify them. `--application <app.manifest>` signs the application manifest first and refreshes the deployment manifests' reference to it (size, digest, publicKeyToken). Also `--timestamp-url`, `--description`, `--description-url`, `--no-login`. See [ClickOnce / VSTO manifests](#clickonce--vsto-manifests). |
| `sigilune verify-manifest <manifests…>` | Verify manifest signatures with the .NET Framework ClickOnce verifier; `--signer <CN>`, `--allow-no-timestamp`, `--no-revocation`. |
| `sigilune sign-hash <digest>` | Sign one SHA-256 digest (64 hex digits or Base64) and print the RSA PKCS#1 v1.5 signature as Base64. Low-level building block for other signing tools. |
| `sigilune cert [--out cert.cer] [--intermediate-out ca.cer]` | Show or export the signing certificate (and its issuing intermediate CA). |
| `sigilune logout [--forget]` | Delete the cached session; `--forget` also deletes the stored registration. |

## Using it from build tools

**Velopack**

```powershell
vpk pack ... --signTemplate "sigilune sign --skip-signed {{file}}"
```

Each invocation is a separate process; they share one login. vpk may pass files that are already signed (for example Microsoft DLLs in a subfolder); `--skip-signed` leaves those untouched. To re-sign them with your certificate instead, use `--replace`.

**Plain signtool** (other tools that can call signtool): log in first, then point signtool at the dlib.

```powershell
sigilune login
signtool sign /fd SHA256 /tr http://time.certum.pl /td SHA256 /dlib C:\tools\sigilune\sigilune_dlib.dll MyApp.exe
```

The dlib uses the cached session, or logs in with the stored registration if there is none.

**Scripts / CI on your own machine**: `sigilune sign` exits non-zero on any signing or verification failure; add `--json` for machine-readable results.

## ClickOnce / VSTO manifests

ClickOnce and VSTO add-ins carry XML signatures in their manifests in addition to the Authenticode signatures on the binaries. `signtool` cannot produce those, so Sigilune ships `sigilune-manifest.exe`, a port of MSBuild's manifest signer (`mansign2.cs`), which asks `sigilune` to sign each digest in the cloud.

```powershell
# 1. Authenticode-sign the binaries first (the manifests record their digests)
sigilune sign .\publish\MyAddIn.dll .\publish\setup.exe
# 2. Refresh the application manifest's file hashes if a binary changed (e.g. with mage -Update), then:
sigilune sign-manifest --application ".\publish\Application Files\MyAddIn_1_0_0_0\MyAddIn.dll.manifest" .\publish\MyAddIn.vsto
```

- The output matches `mage.exe -Sign` byte for byte (checked in CI), plus an RFC 3161 timestamp from Certum and the intermediate CA in the signature.
- After signing, each manifest is checked with the same .NET Framework verifier ClickOnce / VSTO use at install time: XML signature, publisher identity, certificate chain and timestamp.
- Requires .NET Framework 4.8 (built into Windows 10 1903+ / 11) and `sigilune-manifest.exe` next to `sigilune.exe` (set `SIGILUNE_MANIFEST_TOOL` to use another path).
- Whether end users are prompted on install still depends on their Trusted Publishers store, exactly as with a locally signed manifest; `verify-manifest` reports it but does not require it.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `SIGILUNE_EMAIL` + `SIGILUNE_TOTP_URI` | Account e-mail and `otpauth://` URI for CI, used instead of Credential Manager. Set both or neither. On GitHub Actions, keep them as secrets of an Environment limited to your release branches. |
| `SIGILUNE_SIGNTOOL` | Path to `signtool.exe` (default: newest Windows SDK). |
| `SIGILUNE_DLIB` | Path to `sigilune_dlib.dll` (default: next to `sigilune.exe`). |
| `SIGILUNE_CREDENTIAL` | Credential Manager entry name (default `Sigilune/Certum SimplySign`); use different names for several accounts. |
| `SIGILUNE_HOME` | Absolute folder for the session cache (default `%LOCALAPPDATA%\Sigilune`). |
| `SIGILUNE_MANIFEST_TOOL` | Path to `sigilune-manifest.exe` (default: next to `sigilune.exe`). |

## Caveats

- The SimplySign cloud protocol is **not officially documented**. It was reverse-engineered by the ssign project and may change without notice. Sigilune pins `ssign-core` to an exact version.
- Automating the TOTP turns the second factor into something stored on this PC. Whether that is acceptable under your certificate's terms and your own security policy is your decision. Sigilune is not affiliated with or endorsed by Certum / Asseco; "Certum" and "SimplySign" are their trademarks.
- SHA-256 only (`/fd SHA256`).
- Using SimplySign Desktop on the same machine at the same time is fine; Sigilune does not touch it.
- Processes started from inside a packaged (MSIX) app may see a redirected `%LOCALAPPDATA%`, so they keep a separate session cache from your normal terminal. That only costs an extra login; set `SIGILUNE_HOME` to share one folder.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
