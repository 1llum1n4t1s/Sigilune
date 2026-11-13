# sigilune-manifest.exe（MSBuild の mansign2.cs を移植した ClickOnce 署名）の回帰テスト。
#
# Microsoft 公式の mage.exe と同じ使い捨てテスト鍵で署名し、出力がバイト単位で一致することを確かめる。
# RSA PKCS#1 v1.5 は決定的なので、タイムスタンプを付けなければ同一になる。Certum のクラウドには接続しない。
#   1. アプリケーション マニフェストの署名
#   2. 配置マニフェストの参照更新（サイズ・ダイジェスト・公開鍵トークン）と署名（mage -Update と比べる）
#   3. .NET Framework の ClickOnce 検証で合格し、改ざんすると不合格になること
#
# 使い方: pwsh -File tests/Test-ManifestSigning.ps1 -Tool <sigilune-manifest.exe> -WorkDirectory <空または未作成の絶対パス>
# 作業フォルダーは削除しない（CI ではランナーと一緒に消える。ローカルでは各自で片付ける）。
param(
    [Parameter(Mandatory)][string]$Tool,
    [Parameter(Mandatory)][string]$WorkDirectory,
    [string]$Mage
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not [IO.Path]::IsPathFullyQualified($WorkDirectory)) { throw 'WorkDirectory must be an absolute path' }
if ((Test-Path -LiteralPath $WorkDirectory) -and @(Get-ChildItem -LiteralPath $WorkDirectory -Force).Count) {
    throw "WorkDirectory is not empty: $WorkDirectory"
}
$Tool = (Resolve-Path -LiteralPath $Tool).Path
if (-not $Mage) {
    # .NET Framework 4.8 / 4.8.1 SDK の mage.exe（GitHub の windows ランナーにも入っている）。
    $Mage = Get-ChildItem 'C:\Program Files (x86)\Microsoft SDKs\Windows\*\bin\NETFX 4.8*Tools\mage.exe' -ErrorAction SilentlyContinue |
        Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}
if (-not $Mage -or -not (Test-Path -LiteralPath $Mage)) { throw 'mage.exe (.NET Framework 4.8 SDK tools) was not found' }

function Invoke-Checked {
    param([string]$Description, [scriptblock]$Block)
    $output = & $Block 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$Description failed (exit $LASTEXITCODE): $($output -join "`n")" }
}

function Assert-SameFile {
    param([string]$Expected, [string]$Actual, [string]$Case)
    $a = [IO.File]::ReadAllBytes($Expected)
    $b = [IO.File]::ReadAllBytes($Actual)
    if (-not [Linq.Enumerable]::SequenceEqual($a, $b)) {
        throw "[$Case] output differs from mage.exe ($($a.Length) vs $($b.Length) bytes): $Actual"
    }
    Write-Host "PASS [$Case] identical to mage.exe ($($b.Length) bytes)"
}

$root = [IO.Path]::GetFullPath($WorkDirectory)
$template = Join-Path $root 'template'
$payload = Join-Path $template 'payload'
New-Item -ItemType Directory -Force -Path $payload | Out-Null

# 見本のアプリケーション / 配置マニフェストを mage で作る（中身の実行ファイルは何でもよい）。
Copy-Item -LiteralPath $Tool -Destination (Join-Path $payload 'sigilune-manifest.exe')
Push-Location $template
try {
    Invoke-Checked 'mage -New Application' { & $Mage -New Application -ToFile Sample.exe.manifest -Name Sample -Version 1.0.0.0 -FromDirectory payload -Processor msil }
    Invoke-Checked 'mage -New Deployment' { & $Mage -New Deployment -ToFile Sample.application -Name Sample -Version 1.0.0.0 -AppManifest Sample.exe.manifest -Install false -Processor msil }
} finally {
    Pop-Location
}

# 使い捨ての自己署名コード署名証明書（証明書ストアには入れない）。
$rsa = [Security.Cryptography.RSA]::Create(2048)
$request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=Sigilune Manifest Test', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
$eku = [Security.Cryptography.OidCollection]::new()
[void]$eku.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
$request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false))
$certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(7))
$password = [Guid]::NewGuid().ToString('N')
$pfx = Join-Path $root 'test.pfx'
[IO.File]::WriteAllBytes($pfx, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $password))

$mageDir = Join-Path $root 'mage'
$oursDir = Join-Path $root 'ours'
foreach ($d in $mageDir, $oursDir) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
    Copy-Item -Path (Join-Path $template 'Sample.*') -Destination $d
}

$env:SIGILUNE_TEST_PFX_PASSWORD = $password
try {
    # 1. アプリケーション マニフェスト
    Invoke-Checked 'mage -Sign (application)' { & $Mage -Sign (Join-Path $mageDir 'Sample.exe.manifest') -CertFile $pfx -Password $password }
    Invoke-Checked 'sigilune-manifest sign (application)' { & $Tool sign --test-pfx $pfx --no-timestamp (Join-Path $oursDir 'Sample.exe.manifest') }
    Assert-SameFile (Join-Path $mageDir 'Sample.exe.manifest') (Join-Path $oursDir 'Sample.exe.manifest') 'application manifest'

    # 2. 配置マニフェスト: 署名済みアプリケーション マニフェストへの参照を更新してから署名する。
    #    sigilune-manifest は --application を先に署名し直す（同じ鍵・同じ内容なので結果は変わらない）。
    Invoke-Checked 'sigilune-manifest sign --application' { & $Tool sign --test-pfx $pfx --no-timestamp --application (Join-Path $oursDir 'Sample.exe.manifest') (Join-Path $oursDir 'Sample.application') }
    Assert-SameFile (Join-Path $mageDir 'Sample.exe.manifest') (Join-Path $oursDir 'Sample.exe.manifest') 'application manifest (re-signed)'

    # 2a. 参照の更新だけを sigilune-manifest で行い、署名は mage に任せた結果と一致すること（署名部分の比較）。
    #     mage -Update は配置マニフェスト全体を作り直す（compatibleFrameworks なども落とす）ためバイト比較には使えない。
    Invoke-Checked 'sigilune-manifest update-reference' { & $Tool update-reference (Join-Path $mageDir 'Sample.application') (Join-Path $mageDir 'Sample.exe.manifest') }
    Invoke-Checked 'mage -Sign (deployment)' { & $Mage -Sign (Join-Path $mageDir 'Sample.application') -CertFile $pfx -Password $password }
    Assert-SameFile (Join-Path $mageDir 'Sample.application') (Join-Path $oursDir 'Sample.application') 'deployment manifest'

    # 2b. 参照の値（サイズ・ダイジェスト・公開鍵トークン）が mage -Update の計算と一致すること。
    $updated = Join-Path $root 'mage-update'
    New-Item -ItemType Directory -Force -Path $updated | Out-Null
    Copy-Item -Path (Join-Path $template 'Sample.application') -Destination $updated
    Copy-Item -Path (Join-Path $mageDir 'Sample.exe.manifest') -Destination $updated
    Invoke-Checked 'mage -Update (deployment)' { & $Mage -Update (Join-Path $updated 'Sample.application') -AppManifest (Join-Path $updated 'Sample.exe.manifest') -CertFile $pfx -Password $password }
    $xpath = "/*[local-name()='assembly']/*[local-name()='dependency']/*[local-name()='dependentAssembly']"
    $expected = ([xml](Get-Content -LiteralPath (Join-Path $updated 'Sample.application') -Raw)).SelectSingleNode($xpath)
    $actual = ([xml](Get-Content -LiteralPath (Join-Path $oursDir 'Sample.application') -Raw)).SelectSingleNode($xpath)
    $facts = @{
        size = { param($n) $n.GetAttribute('size') }
        digest = { param($n) $n.SelectSingleNode("*[local-name()='hash']/*[local-name()='DigestValue']").InnerText }
        publicKeyToken = { param($n) $n.SelectSingleNode("*[local-name()='assemblyIdentity']").GetAttribute('publicKeyToken') }
    }
    foreach ($name in $facts.Keys) {
        $want = & $facts[$name] $expected
        $got = & $facts[$name] $actual
        if ($want -cne $got) { throw "[reference] $name differs from mage -Update: $got (want $want)" }
    }
    Write-Host 'PASS [reference] size, digest and publicKeyToken match mage -Update'
} finally {
    Remove-Item Env:SIGILUNE_TEST_PFX_PASSWORD -ErrorAction SilentlyContinue
}

# 3. ClickOnce の検証（自己署名なのでチェーンの信頼とタイムスタンプは問わない）。
Invoke-Checked 'sigilune-manifest verify' {
    & $Tool verify --allow-no-timestamp --allow-untrusted-chain --no-revocation --signer 'Sigilune Manifest Test' (Join-Path $oursDir 'Sample.exe.manifest') (Join-Path $oursDir 'Sample.application')
}
Write-Host 'PASS [verify] signed manifests pass the ClickOnce verifier'

$tampered = Join-Path $root 'tampered.application'
$original = Get-Content -LiteralPath (Join-Path $oursDir 'Sample.application') -Raw
$modified = $original -replace 'asmv2:product="Sample"', 'asmv2:product="Tampered"'
# 置換が空振りすると「改ざんしていないものが合格」になり検査にならないため、先に確かめる。
if ($modified -ceq $original) { throw '[tamper] the test could not modify the manifest' }
Set-Content -LiteralPath $tampered -Value $modified -NoNewline -Encoding utf8
& $Tool verify --allow-no-timestamp --allow-untrusted-chain --no-revocation $tampered | Out-Null
if ($LASTEXITCODE -eq 0) { throw '[tamper] a modified manifest passed verification' }
Write-Host 'PASS [tamper] a modified manifest fails verification'
