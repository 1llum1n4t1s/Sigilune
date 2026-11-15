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

# 配布バイナリの署名者（Certum のコード署名証明書の CN）。証明書の更新で拇印が変わっても CN で照合する。
# 配布元は GitHub Release ではなく R2（-BaseUrl）。ここが配信の唯一の入口になる。
$ExpectedSigner = 'Open Source Developer Yuichiro Shinozaki'
$Binaries = @('sigilune.exe', 'sigilune_dlib.dll')
# 1.1.0 で追加した ClickOnce / VSTO マニフェスト署名の補助ツール。古い版の zip には無いので、あるときだけ検証して入れる。
$OptionalBinaries = @('sigilune-manifest.exe')
$OptionalFiles = @('sigilune-manifest.exe.config')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }

if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Sigilune runs on Windows only.' }
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Sigilune requires 64-bit Windows.' }
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
    Write-Warning 'Only an x64 build is published. It runs under emulation on ARM64, but signtool must then be the x64 one.'
}
# Windows PowerShell 5.1 の既定は TLS 1.0 のことがあるため、TLS 1.2 を有効にする。
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$work = Join-Path ([IO.Path]::GetTempPath()) ('sigilune-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    if ($ZipPath) {
        $zip = (Resolve-Path -LiteralPath $ZipPath).ProviderPath
        Write-Step "Using local package $zip"
    } else {
        # 配布元は https 限定（テスト用にループバックだけ http を許す）。リダイレクトは辿らない。
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
        # 版は x.y.z だけ。キーは版から組み立て、フィードの値は照合に使うだけにして、任意のパスへ飛ばされないようにする。
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
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $entries = @(if ($userPath) { $userPath -split ';' | Where-Object { $_ } })
        if (-not ($entries | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') })) {
            [Environment]::SetEnvironmentVariable('Path', (@($entries + $InstallDir) -join ';'), 'User')
            Write-Step 'Added to the user PATH (open a new terminal to use it)'
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
