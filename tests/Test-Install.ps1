#requires -Version 7.2
<#
.SYNOPSIS
install.ps1（R2 からの取得）と scripts/Publish-R2.ps1（入力検査）をローカルのモック HTTP で確かめる。

.DESCRIPTION
本物の R2 にも Certum にも接続しない。モックは 127.0.0.1 の HttpListener（install.ps1 はループバックだけ http を許す）。
モックの zip は署名されていないので、正常系は「取得・SHA-256 照合を通り、署名の検査で止まる」ことで確かめる
（署名の検査を迂回する口は install.ps1 に無い）。確かめること:
  - latest.json の解決と、版付きキー（<ver>/…zip, …zip.sha256）の取得
  - -Version 指定では latest.json を読まない
  - .sha256 と zip が違えば SHA-256 不一致で失敗
  - latest.json が想定外のパスを指していれば失敗
  - 非ループバックの http は拒否
  - Publish-R2.ps1 -ValidateOnly: 正常系と、.sha256 不一致・zip 名違いの失敗
#>
[CmdletBinding()]
param(
    [string]$WorkDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('sigilune-install-test-' + [guid]::NewGuid().ToString('N')))
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).ProviderPath
$install = Join-Path $repo 'install.ps1'
$publish = Join-Path $repo 'scripts/Publish-R2.ps1'
New-Item -ItemType Directory -Path $WorkDirectory -Force | Out-Null

$failures = [System.Collections.Generic.List[string]]::new()
function Assert-That([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host "  ok   $Message" } else { Write-Host "  FAIL $Message" -ForegroundColor Red; $failures.Add($Message) }
}

# --- 偽の配布物 ---------------------------------------------------------------------------------
function New-FakePackage([string]$Version, [string]$Dir) {
    $src = Join-Path $Dir "src-$Version"
    New-Item -ItemType Directory -Path $src -Force | Out-Null
    foreach ($f in 'sigilune.exe', 'sigilune_dlib.dll') { Set-Content -LiteralPath (Join-Path $src $f) -Value "fake $f $Version" }
    $name = "sigilune-$Version-win-x64.zip"
    $zip = Join-Path $Dir $name
    Compress-Archive -Path (Join-Path $src '*') -DestinationPath $zip -Force
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name" | Set-Content -LiteralPath "$zip.sha256" -Encoding ascii -NoNewline
    return $zip
}

$pkg = Join-Path $WorkDirectory 'pkg'
New-Item -ItemType Directory -Path $pkg -Force | Out-Null
$zip = New-FakePackage '9.9.9' $pkg
$zipBytes = [IO.File]::ReadAllBytes($zip)
$sumBytes = [IO.File]::ReadAllBytes("$zip.sha256")
$badSumBytes = [Text.Encoding]::ASCII.GetBytes(('0' * 64) + '  sigilune-9.9.9-win-x64.zip')

# --- モックサーバー -----------------------------------------------------------------------------
$port = Get-Random -Minimum 20000 -Maximum 40000
$prefix = "http://127.0.0.1:$port/"
$routes = [hashtable]::Synchronized(@{})
$requests = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
$listener = [Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
$listener.Start()
$serverJob = Start-ThreadJob -ArgumentList $listener, $routes, $requests -ScriptBlock {
    param($listener, $routes, $requests)
    while ($listener.IsListening) {
        try { $ctx = $listener.GetContext() } catch { break }
        $path = $ctx.Request.Url.AbsolutePath
        [void]$requests.Add($path)
        if ($routes.ContainsKey($path)) {
            $bytes = [byte[]]$routes[$path]
            $ctx.Response.StatusCode = 200
            $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        } else { $ctx.Response.StatusCode = 404 }
        $ctx.Response.Close()
    }
}

function Set-Feed([string]$Zip, [string]$Sha256) {
    $routes['/latest.json'] = [Text.Encoding]::UTF8.GetBytes((@{ version = '9.9.9'; zip = $Zip; sha256 = $Sha256 } | ConvertTo-Json -Compress))
}
function Invoke-Install([string[]]$ExtraArgs) {
    $requests.Clear()
    $target = Join-Path $WorkDirectory ('install-' + [guid]::NewGuid().ToString('N'))
    $out = & pwsh -NoProfile -File $install -BaseUrl $prefix -InstallDir $target -NoPath @ExtraArgs 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out; Requests = @($requests.ToArray()) }
}

try {
    $routes['/9.9.9/sigilune-9.9.9-win-x64.zip'] = $zipBytes
    $routes['/9.9.9/sigilune-9.9.9-win-x64.zip.sha256'] = $sumBytes
    Set-Feed '9.9.9/sigilune-9.9.9-win-x64.zip' '9.9.9/sigilune-9.9.9-win-x64.zip.sha256'

    Write-Host 'latest.json 解決（署名の検査まで進んで止まる）'
    $r = Invoke-Install @()
    Assert-That ($r.ExitCode -ne 0 -and $r.Output -match 'Checksum OK' -and $r.Output -match 'Untrusted signature') 'latest -> 取得・SHA-256 照合を通り、署名の検査で止まる'
    Assert-That (($r.Requests -contains '/latest.json') -and ($r.Requests -contains '/9.9.9/sigilune-9.9.9-win-x64.zip') -and ($r.Requests -contains '/9.9.9/sigilune-9.9.9-win-x64.zip.sha256')) 'latest.json と版付きの zip / .sha256 を取得する'

    Write-Host '-Version 指定'
    $r = Invoke-Install @('-Version', 'v9.9.9')
    Assert-That ($r.Output -match 'Checksum OK' -and $r.Output -match 'Untrusted signature') '-Version v9.9.9 でも同じ経路（先頭の v は無視）'
    Assert-That ($r.Requests -notcontains '/latest.json') '-Version 指定では latest.json を読まない'
    $r = Invoke-Install @('-Version', '1.0.0')
    Assert-That ($r.ExitCode -ne 0 -and $r.Requests -contains '/1.0.0/sigilune-1.0.0-win-x64.zip') '存在しない版は 404 で失敗する'
    $r = Invoke-Install @('-Version', '1.0')
    Assert-That ($r.ExitCode -ne 0 -and $r.Output -match "Invalid version") '版の形式が違えば失敗する'

    Write-Host 'SHA-256 不一致'
    $routes['/9.9.9/sigilune-9.9.9-win-x64.zip.sha256'] = $badSumBytes
    $r = Invoke-Install @()
    Assert-That ($r.ExitCode -ne 0 -and $r.Output -match 'SHA-256 mismatch') '.sha256 と zip が違えば失敗する'
    Assert-That ($r.Output -notmatch 'Checksum OK') '不一致のときは「Checksum OK」を出さない'
    $routes['/9.9.9/sigilune-9.9.9-win-x64.zip.sha256'] = $sumBytes

    Write-Host '想定外の latest.json'
    Set-Feed '../evil.zip' '9.9.9/sigilune-9.9.9-win-x64.zip.sha256'
    $r = Invoke-Install @()
    Assert-That ($r.ExitCode -ne 0 -and $r.Output -match 'unexpected files') 'latest.json が想定外のパスを指せば失敗し、取りに行かない'
    Assert-That (-not ($r.Requests | Where-Object { $_ -like '*evil*' })) '想定外のパスへは接続しない'

    Write-Host 'HTTPS 限定'
    $target = Join-Path $WorkDirectory 'install-http'
    $out = & pwsh -NoProfile -File $install -BaseUrl 'http://example.com' -InstallDir $target -NoPath 2>&1 | Out-String
    Assert-That ($LASTEXITCODE -ne 0 -and $out -match 'BaseUrl must be https') '非ループバックの http は拒否する'

    Write-Host 'Publish-R2.ps1 -ValidateOnly'
    $out = & pwsh -NoProfile -File $publish -Version 9.9.9 -ZipPath $zip -ValidateOnly 2>&1 | Out-String
    Assert-That ($LASTEXITCODE -eq 0 -and $out -match '"zip":"9\.9\.9/sigilune-9\.9\.9-win-x64\.zip"' -and $out -match 'no network access') '正常な入力で latest.json を組み立てる（接続しない）'
    $out = & pwsh -NoProfile -File $publish -Version 9.9.8 -ZipPath $zip -ValidateOnly 2>&1 | Out-String
    Assert-That ($LASTEXITCODE -ne 0 -and $out -match 'must be named') 'zip 名と版が違えば失敗する'
    $badZip = New-FakePackage '9.9.7' $pkg
    [IO.File]::WriteAllBytes("$badZip.sha256", $badSumBytes)
    $out = & pwsh -NoProfile -File $publish -Version 9.9.7 -ZipPath $badZip -ValidateOnly 2>&1 | Out-String
    Assert-That ($LASTEXITCODE -ne 0 -and $out -match 'does not match the zip') '.sha256 が zip と違えば失敗する'
    $out = & pwsh -NoProfile -File $publish -Version 9.9.9 -ZipPath $zip -BaseUrl 'http://x.example' -ValidateOnly 2>&1 | Out-String
    Assert-That ($LASTEXITCODE -ne 0 -and $out -match 'must be https') 'Publish の BaseUrl も https 限定'
} finally {
    $listener.Stop()
    $listener.Close()
    Stop-Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job $serverJob -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) { throw "$($failures.Count) check(s) failed: $($failures -join '; ')" }
Write-Host 'All install / publish checks passed.' -ForegroundColor Green
# 失敗系の検査で呼んだ子プロセスの非0終了コードが $LASTEXITCODE に残り、pwsh -File / CI の step を失敗扱いにするため、成功時は明示的に 0 で終える（失敗は上で throw 済み）。
exit 0
