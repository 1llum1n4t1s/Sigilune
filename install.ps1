<#
.SYNOPSIS
Install Sigilune (sigilune.exe + sigilune_dlib.dll) from GitHub Releases.

.DESCRIPTION
Downloads the release zip, checks its SHA-256 against the published checksum, checks that both
binaries carry a valid Authenticode signature from the Sigilune publisher, then installs them and
adds the folder to the user PATH.

  irm https://raw.githubusercontent.com/1llum1n4t1s/Sigilune/main/install.ps1 | iex

Works in Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Version
Release to install, e.g. 1.0.0. Default: the latest release.

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
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\Sigilune'),
    [switch]$NoPath,
    [string]$ZipPath,
    [switch]$KeepDownload
)

# 配布元と、配布バイナリの署名者（Certum のコード署名証明書の CN）。証明書の更新で拇印が変わっても CN で照合する。
$Repository = '1llum1n4t1s/Sigilune'
$ExpectedSigner = 'Open Source Developer Yuichiro Shinozaki'
$Binaries = @('sigilune.exe', 'sigilune_dlib.dll')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }

if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Sigilune runs on Windows only.' }
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Sigilune requires 64-bit Windows.' }
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
    Write-Warning 'Only an x64 build is published. It runs under emulation on ARM64, but signtool must then be the x64 one.'
}
# Windows PowerShell 5.1 の既定は TLS 1.0 のことがあるため、GitHub に必要な TLS 1.2 を有効にする。
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$work = Join-Path ([IO.Path]::GetTempPath()) ('sigilune-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    if ($ZipPath) {
        $zip = (Resolve-Path -LiteralPath $ZipPath).ProviderPath
        Write-Step "Using local package $zip"
    } else {
        $api = if ($Version -eq 'latest') { "https://api.github.com/repos/$Repository/releases/latest" } else { "https://api.github.com/repos/$Repository/releases/tags/v$($Version.TrimStart('v'))" }
        Write-Step "Looking up release ($Version)"
        $release = Invoke-RestMethod -Uri $api -Headers @{ 'User-Agent' = 'sigilune-installer'; Accept = 'application/vnd.github+json' }
        $asset = @($release.assets | Where-Object { $_.name -match '^sigilune-.+-win-x64\.zip$' }) | Select-Object -First 1
        $sumAsset = @($release.assets | Where-Object { $asset -and $_.name -eq ($asset.name + '.sha256') }) | Select-Object -First 1
        if (-not $asset -or -not $sumAsset) { throw "Release $($release.tag_name) has no win-x64 zip with a .sha256 file." }

        $zip = Join-Path $work $asset.name
        $sum = Join-Path $work $sumAsset.name
        Write-Step "Downloading $($asset.name)"
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing -Headers @{ 'User-Agent' = 'sigilune-installer' }
        Invoke-WebRequest -Uri $sumAsset.browser_download_url -OutFile $sum -UseBasicParsing -Headers @{ 'User-Agent' = 'sigilune-installer' }

        $expected = ((Get-Content -LiteralPath $sum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
        $actual = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expected -ne $actual) { throw "SHA-256 mismatch for $($asset.name) (expected $expected, got $actual)." }
        Write-Step 'Checksum OK'
    }

    $extract = Join-Path $work 'extract'
    Expand-Archive -LiteralPath $zip -DestinationPath $extract
    foreach ($name in $Binaries) {
        $file = Join-Path $extract $name
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "The package does not contain $name." }
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { '' }
        if ($sig.Status -ne 'Valid' -or $signer -cne $ExpectedSigner) { throw "Untrusted signature on ${name}: status $($sig.Status), signer '$signer'." }
    }
    Write-Step "Signature OK ($ExpectedSigner)"

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    foreach ($name in @($Binaries + @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md'))) {
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
