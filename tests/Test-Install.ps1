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
  - ユーザー PATH の合成（Get-UserPathUpdate）: %VAR% を展開せずに保持・値種別の保持・重複判定・非文字列値の拒否
  - 本体が展開してしまう旧方式（[Environment]::Get/SetEnvironmentVariable の 'User'）へ戻っていないこと（静的検査）
  - install.ps1 が ASCII のみであること（Windows PowerShell 5.1 は BOM なし UTF-8 を CP932 で読むため）と、5.1 の -File 経路
実レジストリ・実 PATH には触れない（install.ps1 の起動はすべて -NoPath、PATH 合成は AST から取り出した関数だけを実行する）。
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

    # --- ユーザー PATH の合成（純関数。実レジストリ・実 PATH には触れない） ---
    # install.ps1 から Get-UserPathUpdate の定義だけを AST で取り出して実行する（スクリプト本体は走らせない）。
    Write-Host 'ユーザー PATH の合成（展開・種別保持・重複判定・空値・非文字列値）'
    $psTokens = $null; $psErrors = $null
    $psAst = [Management.Automation.Language.Parser]::ParseFile($install, [ref]$psTokens, [ref]$psErrors)
    Assert-That (@($psErrors).Count -eq 0) 'install.ps1 は構文として解釈できる'
    $pathFnAst = $psAst.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-UserPathUpdate' }, $true) | Select-Object -First 1
    Assert-That ($null -ne $pathFnAst) 'install.ps1 に Get-UserPathUpdate がある'
    # 本体が非展開で読む新方式を使い続けていることを静的に確かめる（レジストリには触れない）。
    # [Environment]::Get/SetEnvironmentVariable の 'User' は REG_EXPAND_SZ を展開して REG_SZ で書き戻すため使わない。
    $envApiCalls = $psAst.FindAll({ param($n) $n -is [Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Extent.Text -in @('GetEnvironmentVariable', 'SetEnvironmentVariable') }, $true)
    Assert-That (@($envApiCalls).Count -eq 0) 'install.ps1 は [Environment]::Get/SetEnvironmentVariable でユーザー PATH を読み書きしない'
    $addCalls = $psAst.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-ToUserPath' }, $true)
    Assert-That (@($addCalls).Count -ge 1) 'install.ps1 の本体が Add-ToUserPath で PATH を更新する'
    $pathFnText = $pathFnAst.Extent.Text
    . ([scriptblock]::Create($pathFnText))
    $kExpand = [Microsoft.Win32.RegistryValueKind]::ExpandString
    $kString = [Microsoft.Win32.RegistryValueKind]::String
    $savedTestBin = $env:SIGILUNE_TEST_BIN
    $env:SIGILUNE_TEST_BIN = 'C:\SigiluneTest\bin'
    try {
        $u = Get-UserPathUpdate $true '%SIGILUNE_TEST_BIN%;C:\Tools' $kExpand 'C:\New\Sigilune'
        Assert-That ($u.Value -ceq '%SIGILUNE_TEST_BIN%;C:\Tools;C:\New\Sigilune') '既存の項目は展開せずそのまま残して末尾へ追加する'
        Assert-That ($u.Kind -eq $kExpand) '元の値種別（REG_EXPAND_SZ）を保つ'
        $u = Get-UserPathUpdate $true 'C:\Tools' $kString 'C:\New\Sigilune'
        Assert-That ($u.Kind -eq $kString -and $u.Value -ceq 'C:\Tools;C:\New\Sigilune') '元が REG_SZ なら REG_SZ のまま書き戻す'
        $u = Get-UserPathUpdate $false '' $null 'C:\New\Sigilune'
        Assert-That ($u.Value -ceq 'C:\New\Sigilune' -and $u.Kind -eq $kExpand) '値が無ければ REG_EXPAND_SZ で新規に作る'
        $u = Get-UserPathUpdate $true 'C:\A;' $kExpand 'C:\New\Sigilune'
        Assert-That ($u.Value -ceq 'C:\A;C:\New\Sigilune') '末尾の区切りは重ねない'
        $u = Get-UserPathUpdate $true '' $kExpand 'C:\New\Sigilune'
        Assert-That ($u.Value -ceq 'C:\New\Sigilune') '空の値には項目だけを入れる'
        Assert-That ($null -eq (Get-UserPathUpdate $true 'C:\Tools;C:\New\Sigilune\' $kExpand 'c:\new\SIGILUNE')) '末尾の \ と大文字小文字の違いは重複とみなす'
        Assert-That ($null -eq (Get-UserPathUpdate $true '%SIGILUNE_TEST_BIN%;C:\Tools' $kExpand 'c:\sigiluneTEST\BIN\')) '環境変数を展開した結果が同じなら重複とみなす（追加しない）'
        Assert-That ($null -eq (Get-UserPathUpdate $true 'C:\Tools;C:\SigiluneTest\bin' $kExpand '%SIGILUNE_TEST_BIN%')) '追加する側が環境変数参照でも展開して比べる'
        $threw = $false
        try { Get-UserPathUpdate $true 'C:\Tools' ([Microsoft.Win32.RegistryValueKind]::DWord) 'C:\New' | Out-Null } catch { $threw = $true }
        Assert-That $threw '文字列型でない Path の値は壊さずに止まる'
    } finally {
        if ($null -eq $savedTestBin) { Remove-Item Env:SIGILUNE_TEST_BIN -ErrorAction SilentlyContinue } else { $env:SIGILUNE_TEST_BIN = $savedTestBin }
    }
    # Windows PowerShell 5.1 でも同じ結果になること（導入先は 5.1 のことが多い）。
    $ps51 = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($ps51) {
        $ps51Script = Join-Path $WorkDirectory 'ps51-path.ps1'
        $ps51Body = @(
            '$env:SIGILUNE_TEST_BIN = ''C:\SigiluneTest\bin''',
            $pathFnText,
            '$u = Get-UserPathUpdate $true ''%SIGILUNE_TEST_BIN%;C:\Tools'' ([Microsoft.Win32.RegistryValueKind]::ExpandString) ''C:\New\Sigilune''',
            'Write-Output ("add=" + $u.Value + "|" + $u.Kind)',
            '$d = Get-UserPathUpdate $true ''%SIGILUNE_TEST_BIN%;C:\Tools'' ([Microsoft.Win32.RegistryValueKind]::ExpandString) ''c:\sigiluneTEST\BIN\''',
            'Write-Output ("dup=" + ($null -eq $d))'
        ) -join "`n"
        [IO.File]::WriteAllText($ps51Script, $ps51Body, [Text.UTF8Encoding]::new($false))
        $out = & $ps51.Source -NoProfile -ExecutionPolicy Bypass -File $ps51Script 2>&1 | Out-String
        Assert-That ($out -match 'add=%SIGILUNE_TEST_BIN%;C:\\Tools;C:\\New\\Sigilune\|ExpandString' -and $out -match 'dup=True') 'powershell.exe 5.1 でも同じ結果になる'
    }

    # install.ps1 は保存して 5.1 で実行され得る（README の保存実行）ため ASCII だけにしてある（BOM なし UTF-8 の日本語は CP932 として読まれ、改行を巻き込む）。
    Write-Host 'install.ps1 は ASCII のみ・powershell.exe 5.1 -File でも動く'
    $nonAscii = @([IO.File]::ReadAllBytes($install) | Where-Object { $_ -gt 127 }).Count
    Assert-That ($nonAscii -eq 0) 'install.ps1 は ASCII だけで書かれている'
    if ($ps51) {
        $requests.Clear()
        $target = Join-Path $WorkDirectory 'install-ps51'
        $out = & $ps51.Source -NoProfile -ExecutionPolicy Bypass -File $install -BaseUrl $prefix -InstallDir $target -NoPath 2>&1 | Out-String
        Assert-That ($LASTEXITCODE -ne 0 -and $out -match 'Checksum OK' -and $out -match 'Untrusted signature') 'powershell.exe 5.1 -File でも取得・照合を通り、署名の検査で止まる'
    } else {
        Write-Host '  skip powershell.exe が無いため 5.1 の検査は省略'
    }

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
