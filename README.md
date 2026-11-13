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

## Install

Once releases are published: download `sigilune-<version>-win-x64.zip` from Releases and put `sigilune.exe` and `sigilune_dlib.dll` in the same folder on your `PATH`.

From source:

```powershell
cargo build --release
# target\release\sigilune.exe and target\release\sigilune_dlib.dll
```

## Commands

| Command | What it does |
| --- | --- |
| `sigilune setup --email <e-mail>` | Store the registration. The `otpauth://` URI (or Base32 seed) is read from a hidden prompt, or from stdin when piped. `--from-json <file> --email-pointer <ptr> --uri-pointer <ptr>` imports from a JSON secrets file. |
| `sigilune login` | Log in now (reuses a valid cached session). |
| `sigilune status` | Show the registration and cached session without contacting Certum. |
| `sigilune sign <files…>` | Sign with signtool + the dlib, then verify. Refuses already-signed files unless `--replace` (overwrite). Nested signatures are not supported yet. Also `--timestamp-url`, `--description`, `--description-url`, `--no-login`, `--json`. |
| `sigilune verify <files…>` | Verify validity and timestamp; `--signer <CN>` requires a signer; `--allow-no-timestamp`; `--json`. |
| `sigilune cert [--out cert.cer]` | Show or export the signing certificate. |
| `sigilune logout [--forget]` | Delete the cached session; `--forget` also deletes the stored registration. |

## Using it from build tools

**Velopack**

```powershell
vpk pack ... --signTemplate "sigilune sign {{file}}"
```

Each invocation is a separate process; they share one login. If your package contains files that are already signed and you want them re-signed, add `--replace`.

**Plain signtool** (other tools that can call signtool): log in first, then point signtool at the dlib.

```powershell
sigilune login
signtool sign /fd SHA256 /tr http://time.certum.pl /td SHA256 /dlib C:\tools\sigilune\sigilune_dlib.dll MyApp.exe
```

The dlib uses the cached session, or logs in with the stored registration if there is none.

**Scripts / CI on your own machine**: `sigilune sign` exits non-zero on any signing or verification failure; add `--json` for machine-readable results.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `SIGILUNE_SIGNTOOL` | Path to `signtool.exe` (default: newest Windows SDK). |
| `SIGILUNE_DLIB` | Path to `sigilune_dlib.dll` (default: next to `sigilune.exe`). |
| `SIGILUNE_CREDENTIAL` | Credential Manager entry name (default `Sigilune/Certum SimplySign`); use different names for several accounts. |
| `SIGILUNE_HOME` | Absolute folder for the session cache (default `%LOCALAPPDATA%\Sigilune`). |

## Caveats

- The SimplySign cloud protocol is **not officially documented**. It was reverse-engineered by the ssign project and may change without notice. Sigilune pins `ssign-core` to an exact version.
- Automating the TOTP turns the second factor into something stored on this PC. Whether that is acceptable under your certificate's terms and your own security policy is your decision. Sigilune is not affiliated with or endorsed by Certum / Asseco; "Certum" and "SimplySign" are their trademarks.
- SHA-256 only (`/fd SHA256`).
- Using SimplySign Desktop on the same machine at the same time is fine; Sigilune does not touch it.
- Processes started from inside a packaged (MSIX) app may see a redirected `%LOCALAPPDATA%`, so they keep a separate session cache from your normal terminal. That only costs an extra login; set `SIGILUNE_HOME` to share one folder.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
