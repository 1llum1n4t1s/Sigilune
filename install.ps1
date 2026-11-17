<#
.SYNOPSIS
Install Sigilune (sigilune.exe + sigilune_dlib.dll + sigilune-manifest.exe) from the Sigilune download site.

.DESCRIPTION
Downloads the release zip from https://sigilune.kagayoi.com (Cloudflare R2; GitHub Releases are not used),
checks its SHA-256 against the published checksum, checks that every binary carries a valid Authenticode
signature from the Sigilune publisher, then installs them and adds the folder to the user PATH.

Layout of the download site:
  latest.json                               {"version","zip","sha256"} of the newest release
  <ver>/sigilune-<ver>-win-x64.zip          immutable
  <ver>/sigilune-<ver>-win-x64.zip.sha256   immutable

  irm https://raw.githubusercontent.com/1llum1n4t1s/Sigilune/main/install.ps1 | iex

Works in Windows PowerShell 5.1 and PowerShell 7.

NOTE: this file is deliberately ASCII-only (comments and strings in English). It can be saved to disk and run by
Windows PowerShell 5.1, which reads a BOM-less file as the ANSI code page; non-ASCII text can swallow line breaks.

.PARAMETER Version
Release to install, e.g. 1.0.0. Default: the newest release (read from latest.json).

.PARAMETER BaseUrl
Download site. Default: https://sigilune.kagayoi.com. Must be https (plain http only for a loopback
address, so that tests can use a local mock server). The signature check below always applies.

.PARAMETER InstallDir
Default: %LOCALAPPDATA%\Programs\Sigilune

.PARAMETER NoPath
Do not add InstallDir to the user PATH.

.PARAMETER ZipPath
Install from a local release zip instead of downloading (the signature is still checked).

.PARAMETER KeepDownload
Keep the temporary download folder (for troubleshooting).
#>
[CmdletBinding()]
param(
    [string]$Version = 'latest',
    [string]$BaseUrl = 'https://sigilune.kagayoi.com',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Sigilune'),
    [switch]$NoPath,
    [string]$ZipPath,
    [switch]$KeepDownload
)

# Expected signer: the CN of the Certum code-signing certificate. Matched by CN so that a certificate renewal
# (new thumbprint) does not break installs. Downloads come only from R2 (-BaseUrl), not from GitHub Releases.
$ExpectedSigner = 'Open Source Developer Yuichiro Shinozaki'
$Binaries = @('sigilune.exe', 'sigilune_dlib.dll')
# Helper for ClickOnce / VSTO manifest signing, added in 1.1.0. Older zips do not contain it, so it is verified and installed only when present.
$OptionalBinaries = @('sigilune-manifest.exe')
$OptionalFiles = @('sigilune-manifest.exe.config')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }

# --- User PATH helpers ---------------------------------------------------------------------------------------
# The user PATH lives in HKCU\Environment\Path. It is usually REG_EXPAND_SZ and may contain %VAR% references,
# so it is read WITHOUT expanding, written back with its original value kind, and compared entry by entry
# after expanding. [Environment]::GetEnvironmentVariable/SetEnvironmentVariable would flatten the value to an
# expanded REG_SZ string. Get-UserPathUpdate is pure (no registry access); tests load it from this file.

# Returns $null when $Dir is already on the path, else the new raw value and the registry value kind to use.
function Get-UserPathUpdate([bool]$Exists, [string]$Raw, $Kind, [string]$Dir) {
    $string = [Microsoft.Win32.RegistryValueKind]::String
    $expand = [Microsoft.Win32.RegistryValueKind]::ExpandString
    if ($Exists -and $Kind -ne $string -and $Kind -ne $expand) { throw "The user Path has an unexpected registry value type ($Kind)." }
    $want = [Environment]::ExpandEnvironmentVariables($Dir).Trim().TrimEnd('\')
    foreach ($entry in @($Raw -split ';')) {
        if ($entry -and [Environment]::ExpandEnvironmentVariables($entry).Trim().TrimEnd('\') -ieq $want) { return $null }
    }
    # Existing entries are kept verbatim (unexpanded); only a trailing separator is dropped before appending.
    $value = if ($Raw) { $Raw.TrimEnd(';') + ';' + $Dir } else { $Dir }
    # A missing value is created as REG_EXPAND_SZ, the kind Windows itself uses for the user Path.
    $newKind = if ($Exists) { $Kind } else { $expand }
    return [pscustomobject]@{ Value = $value; Kind = $newKind }
}

# Tells running programs (Explorer, new terminals) that the environment changed, as SetEnvironmentVariable did.
function Send-EnvironmentChange {
    try {
        if (-not ('SigiluneInstall.NativeMethods' -as [type])) {
            Add-Type -Namespace SigiluneInstall -Name NativeMethods -MemberDefinition (@(
                '[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]',
                'public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
            ) -join "`n")
        }
        $result = [UIntPtr]::Zero
        # HWND_BROADCAST, WM_SETTINGCHANGE, lParam "Environment", SMTO_ABORTIFHUNG, 5 second timeout.
        [void][SigiluneInstall.NativeMethods]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
    } catch {
        Write-Warning "Could not notify running programs of the PATH change: $($_.Exception.Message)"
    }
}

# Adds $Dir to the user PATH in the registry. Returns $true when it was added, $false when already present.
function Add-ToUserPath([string]$Dir) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        $exists = @($key.GetValueNames()) -contains 'Path'
        $raw = ''
        $kind = $null
        if ($exists) {
            $raw = [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = $key.GetValueKind('Path')
        }
        $update = Get-UserPathUpdate $exists $raw $kind $Dir
        if (-not $update) { return $false }
        $key.SetValue('Path', $update.Value, $update.Kind)
    } finally {
        $key.Close()
    }
    Send-EnvironmentChange
    return $true
}

if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Sigilune runs on Windows only.' }
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Sigilune requires 64-bit Windows.' }
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
    Write-Warning 'Only an x64 build is published. It runs under emulation on ARM64, but signtool must then be the x64 one.'
}
# Windows PowerShell 5.1 may default to TLS 1.0, so enable TLS 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$work = Join-Path ([IO.Path]::GetTempPath()) ('sigilune-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    if ($ZipPath) {
        $zip = (Resolve-Path -LiteralPath $ZipPath).ProviderPath
        Write-Step "Using local package $zip"
    } else {
        # https only (plain http only for loopback, for tests). Redirects are never followed.
        $base = $BaseUrl.TrimEnd('/')
        $baseUri = [uri]$base
        if ($baseUri.Scheme -ne 'https' -and -not ($baseUri.Scheme -eq 'http' -and $baseUri.IsLoopback)) { throw "BaseUrl must be https: $BaseUrl" }
        $web = @{ UseBasicParsing = $true; MaximumRedirection = 0; Headers = @{ 'User-Agent' = 'sigilune-installer' } }

        $want = $Version.TrimStart('v')
        if ($want -eq 'latest') {
            Write-Step 'Looking up the latest release'
            $feed = (Invoke-WebRequest -Uri "$base/latest.json" @web).Content
            if ($feed -is [byte[]]) { $feed = [Text.Encoding]::UTF8.GetString($feed) }
            $latest = $feed | ConvertFrom-Json
            $want = [string]$latest.version
        }
        # The version must be x.y.z. The download keys are built from it; values in the feed are only compared
        # against them, so the feed can never redirect the installer to an arbitrary path.
        if ($want -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid version '$want'." }
        $zipName = "sigilune-$want-win-x64.zip"
        $zipKey = "$want/$zipName"
        if ($Version.TrimStart('v') -eq 'latest' -and ([string]$latest.zip -cne $zipKey -or [string]$latest.sha256 -cne "$zipKey.sha256")) {
            throw "latest.json points to unexpected files for $want."
        }

        $zip = Join-Path $work $zipName
        $sum = "$zip.sha256"
        Write-Step "Downloading $zipName"
        Invoke-WebRequest -Uri "$base/$zipKey" -OutFile $zip @web
        Invoke-WebRequest -Uri "$base/$zipKey.sha256" -OutFile $sum @web

        $expected = ((Get-Content -LiteralPath $sum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
        $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expected -ne $actual) { throw "SHA-256 mismatch for $zipName (expected $expected, got $actual)." }
        Write-Step 'Checksum OK'
    }

    $extract = Join-Path $work 'extract'
    Expand-Archive -LiteralPath $zip -DestinationPath $extract
    $present = @($OptionalBinaries | Where-Object { Test-Path -LiteralPath (Join-Path $extract $_) -PathType Leaf })
    foreach ($name in @($Binaries + $present)) {
        $file = Join-Path $extract $name
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "The package does not contain $name." }
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { '' }
        if ($sig.Status -ne 'Valid' -or $signer -cne $ExpectedSigner) { throw "Untrusted signature on ${name}: status $($sig.Status), signer '$signer'." }
    }
    Write-Step "Signature OK ($ExpectedSigner)"

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    foreach ($name in @($Binaries + $present + $OptionalFiles + @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md'))) {
        $src = Join-Path $extract $name
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $InstallDir -Force }
    }
    Write-Step "Installed to $InstallDir"

    if (-not $NoPath) {
        # The files are already in place, so a PATH problem (for example a Path value of an unexpected registry
        # type, which is left untouched) is only a warning: the install itself still succeeds.
        try {
            if (Add-ToUserPath $InstallDir) { Write-Step 'Added to the user PATH (open a new terminal to use it)' }
        } catch {
            Write-Warning "Installed, but the user PATH was not updated: $($_.Exception.Message) Add $InstallDir to PATH yourself."
        }
        if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') })) { $env:Path = "$env:Path;$InstallDir" }
    }

    & (Join-Path $InstallDir 'sigilune.exe') --version
    Write-Host ''
    Write-Host 'Next: register your Certum SimplySign account (the otpauth:// URI is asked for without echo):' -ForegroundColor Green
    Write-Host '  sigilune setup --email you@example.com'
    Write-Host '  sigilune login'
} finally {
    if ($KeepDownload) { Write-Host "Download kept at $work" }
    else { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
