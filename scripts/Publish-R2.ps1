#requires -Version 7.2
<#
.SYNOPSIS
署名済みの配布 zip を Cloudflare R2（sigilune-updates / https://sigilune.kagayoi.com）へ配信する。

.DESCRIPTION
release.yml（main のコミットへの版タグ v<版> の push）から呼ぶ。GitHub Release は使わず、R2 を唯一の配布元にする。

置き場（バケット直下）:
  <ver>/sigilune-<ver>-win-x64.zip          版付き・不変（immutable）
  <ver>/sigilune-<ver>-win-x64.zip.sha256   版付き・不変（immutable）
  latest.json                               固定名のフィード。最後に置き、固定名だけキャッシュを purge する

配信の順序と安全策:
  1. 入力検査（zip 名・.sha256 の中身が zip の実ハッシュと一致するか）と、bucket・zone の権限確認を、何も書く前に行う。
  2. 版付きファイルを先に置く。同じキーが既にあって内容が同一なら成功（再実行を許す）。
     内容が違えば上書きせず失敗する（署名のタイムスタンプが変わる再ビルドで、同じ版の別内容を上げない）。
  3. 公開 URL（Cloudflare 経由）から版付きファイルを取り直して照合する。公開ドメイン未設定・誤設定のまま
     フィードだけを進めないための確認。
  4. R2 の latest.json の版が今回より新しければ latest.json は更新しない（後退防止）。同じか古ければ更新する。
  5. 固定名（latest.json）だけを purge する。purge の失敗は警告（latest.json は no-cache で配るため）。

認証: 環境変数 CLOUDFLARE_API_TOKEN（R2 書込み＋キャッシュ purge 権限。CI では Environment の Secret）。
転送実装は Edictora と同じ R2Transfer.Core.cs / R2Distribution.Common.ps1（同梱コピー）を使う。
#>
[CmdletBinding()]
param(
    # 配信する版（例 1.1.3）。Cargo.toml の版と一致していること（呼び出し側で保証する）。
    [Parameter(Mandatory)][string]$Version,
    # 署名・検証済みの zip。隣に <zip>.sha256 があること。
    [Parameter(Mandatory)][string]$ZipPath,
    [string]$Bucket = 'sigilune-updates',
    [string]$BaseUrl = 'https://sigilune.kagayoi.com',
    # Cloudflare アカウント ID（秘密ではない。他アプリと同じアカウント）。
    [string]$AccountId = '10901bfadbf1005164774a7350082985',
    # 入力検査と latest.json の生成だけを行い、ネットワークへは一切接続しない（ローカル検証用）。
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "version must look like 1.2.3: $Version" }
$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -notmatch '^https://') { throw "BaseUrl must be https: $BaseUrl" }

# --- 入力検査 ------------------------------------------------------------------------------------
$zipFile = Get-Item -LiteralPath $ZipPath -ErrorAction Stop
$sumFile = Get-Item -LiteralPath "$($zipFile.FullName).sha256" -ErrorAction Stop
$zipName = "sigilune-$Version-win-x64.zip"
if ($zipFile.Name -cne $zipName) { throw "zip must be named $zipName (got $($zipFile.Name))" }

$zipHash = (Get-FileHash -LiteralPath $zipFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$sumText = (Get-Content -LiteralPath $sumFile.FullName -Raw).Trim()
# 形式は `<hash>  <zip 名>`（sha256sum 互換）。install.ps1 は先頭の語だけを使う。
if ($sumText -cne "$zipHash  $zipName") { throw "$($sumFile.Name) does not match the zip (expected '$zipHash  $zipName')" }

$zipKey = "$Version/$zipName"
$sumKey = "$zipKey.sha256"
# フィード。install.ps1 が最小限の項目だけを信用する。zip / sha256 は BaseUrl からの相対パス。
$feed = [ordered]@{ version = $Version; zip = $zipKey; sha256 = $sumKey }
$feedJson = ($feed | ConvertTo-Json -Compress) + "`n"
$work = Join-Path ([IO.Path]::GetTempPath()) ('sigilune-publish-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$feedFile = Join-Path $work 'latest.json'
[IO.File]::WriteAllText($feedFile, $feedJson, [Text.UTF8Encoding]::new($false))
Write-Host "package ok: $zipName sha256=$zipHash"
Write-Host "feed: $($feedJson.Trim())"
if ($ValidateOnly) {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'ValidateOnly: no network access.'
    return
}

try {
    if (-not $env:CLOUDFLARE_API_TOKEN) { throw 'CLOUDFLARE_API_TOKEN is not set' }
    . (Join-Path $PSScriptRoot 'R2Distribution.Common.ps1')
    $api = 'https://api.cloudflare.com/client/v4'
    $headers = @{ Authorization = "Bearer $($env:CLOUDFLARE_API_TOKEN)" }

    # --- 書く前の権限確認（途中まで公開された状態を防ぐ） -----------------------------------------
    $bucketResponse = Invoke-RestMethod -Uri "$api/accounts/$AccountId/r2/buckets/$([uri]::EscapeDataString($Bucket))" `
        -Headers $headers -TimeoutSec 30 -MaximumRedirection 0
    if (-not $bucketResponse.success -or $bucketResponse.result.name -cne $Bucket) { throw "R2 bucket '$Bucket' was not found" }
    # <sub>.kagayoi.com -> kagayoi.com（apex）。キャッシュ purge に zone ID が要る。
    $zoneName = ([uri]$BaseUrl).Host -replace '^[^.]+\.', ''
    $zoneResponse = Invoke-RestMethod -Uri "$api/zones?name=$zoneName" -Headers $headers -TimeoutSec 30 -MaximumRedirection 0
    if (-not $zoneResponse.success -or @($zoneResponse.result).Count -eq 0) { throw "Cloudflare zone '$zoneName' was not found" }
    $zoneId = $zoneResponse.result[0].id

    # --- 後退防止の判定材料: いま公開されている latest.json の版 ----------------------------------
    # 固定名は no-cache で配っているため、公開 URL から読む。無い（404）なら初回配信。
    $remote = Invoke-WebRequest -Uri "$BaseUrl/latest.json" -SkipHttpErrorCheck -MaximumRedirection 0 -TimeoutSec 30
    $remoteVersion = $null
    if ($remote.StatusCode -eq 200) {
        $remoteFeed = $remote.Content | ConvertFrom-Json
        # 壊れたフィードを黙って上書きしない（原因を確かめてから）。
        if (-not ($remoteFeed.PSObject.Properties.Name -contains 'version') -or "$($remoteFeed.version)" -notmatch '^\d+\.\d+\.\d+$') {
            throw "the published latest.json has no valid version; check $BaseUrl/latest.json"
        }
        $remoteVersion = [version]$remoteFeed.version
    } elseif ($remote.StatusCode -ne 404) {
        throw "could not read $BaseUrl/latest.json (HTTP $($remote.StatusCode))"
    }

    # --- 版付き（不変）ファイルを先に置く ----------------------------------------------------------
    # Immutable: 既存と同一なら成功（Changed=false）、既存と内容が違えば照合で失敗し上書きしない。
    $immutableCache = 'public, max-age=31536000, immutable'
    foreach ($item in @(
            @{ File = $zipFile.FullName; Key = $zipKey; Type = 'application/zip' },
            @{ File = $sumFile.FullName; Key = $sumKey; Type = 'text/plain; charset=utf-8' })) {
        $result = Publish-R2Object -AccountId $AccountId -Bucket $Bucket -FilePath $item.File -Key $item.Key `
            -ApiToken $env:CLOUDFLARE_API_TOKEN -ContentType $item.Type -CacheControl $immutableCache -Immutable
        Write-Host ("  {0}  {1}" -f $(if ($result.Changed) { 'uploaded ' } else { 'unchanged' }), $item.Key)
    }

    # --- 公開 URL から取り直して照合（フィードを進める前の最終確認） --------------------------------
    $publicSum = (Invoke-WebRequest -Uri "$BaseUrl/$sumKey" -MaximumRedirection 0 -TimeoutSec 60).Content
    if ($publicSum -is [byte[]]) { $publicSum = [Text.Encoding]::UTF8.GetString($publicSum) }
    if ($publicSum.Trim() -cne "$zipHash  $zipName") { throw "$BaseUrl/$sumKey does not serve the uploaded checksum" }
    $publicZip = Join-Path $work $zipName
    Invoke-WebRequest -Uri "$BaseUrl/$zipKey" -OutFile $publicZip -MaximumRedirection 0 -TimeoutSec 600
    if ((Get-FileHash -LiteralPath $publicZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $zipHash) {
        throw "$BaseUrl/$zipKey does not serve the uploaded zip"
    }
    Write-Host "public URL verified: $BaseUrl/$zipKey"

    # --- フィード（最後） ---------------------------------------------------------------------------
    if ($remoteVersion -and $remoteVersion -gt [version]$Version) {
        # 古い版の再実行などで latest を後退させない。版付きファイルは置いたので配信自体は成功。
        Write-Warning "published latest.json is already $remoteVersion (newer than $Version); latest.json was left unchanged."
        return
    }
    # 固定名は毎回再検証させる。Publish-R2Object は既存の ETag を If-Match に使い、同時更新を検出する。
    $null = Publish-R2Object -AccountId $AccountId -Bucket $Bucket -FilePath $feedFile -Key 'latest.json' `
        -ApiToken $env:CLOUDFLARE_API_TOKEN -ContentType 'application/json' -CacheControl 'no-cache, must-revalidate'
    Write-Host '  uploaded   latest.json'

    # --- 固定名だけ purge（版付きは URL が一意なので不要）。失敗は警告にとどめる -------------------
    try {
        $body = @{ files = @("$BaseUrl/latest.json") } | ConvertTo-Json -Compress
        $purge = Invoke-RestMethod -Method Post -Uri "$api/zones/$zoneId/purge_cache" -Headers $headers `
            -ContentType 'application/json' -Body $body -TimeoutSec 30 -MaximumRedirection 0
        if (-not $purge.success) { throw ($purge.errors | ConvertTo-Json -Compress) }
        Write-Host '  purged     latest.json'
    } catch {
        Write-Warning "uploaded, but the cache purge failed: $($_.Exception.Message)"
    }
    Write-Host "published Sigilune $Version to $BaseUrl"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
