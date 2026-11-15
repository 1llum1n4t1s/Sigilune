# DESIGN.md

Sigilune の現在の設計・境界・データの流れ・不変条件をまとめる。運用手順は [AGENTS.md](AGENTS.md)、利用者向けの説明は [README.md](README.md) を参照する。

## 目的と範囲

- Certum SimplySign のクラウドにあるコード署名用の鍵で、signtool が扱えるすべての形式に Authenticode 署名する。
- SimplySign Desktop と手入力のワンタイムコードを不要にし、ビルドスクリプトや Velopack などから1コマンドで呼べるようにする。
- signtool では署名できない ClickOnce / VSTO マニフェストにも、同じクラウド鍵で XML 署名する。
- 対象は Windows x64。本人の PC のほか、ブランチを制限した Environment の Secrets で GitHub Actions からも署名できる（Sigilune 自身の CI はテスト鍵だけを使う）。

## 構成

| 構成要素 | 種類 | 役割 |
| --- | --- | --- |
| `sigilune-core` | lib | 資格情報（Credential Manager）、DPAPI、セッション、証明書、signtool の起動、WinVerifyTrust による検証 |
| `sigilune` | bin (`sigilune.exe`) | CLI：`setup` / `login` / `status` / `logout` / `sign` / `verify` / `cert` / `sign-manifest` / `verify-manifest` / `sign-hash` |
| `sigilune-dlib` | cdylib (`sigilune_dlib.dll`) | signtool `/dlib` 用：`AuthenticodeDigestSignEx` と `…WithFileHandle` |
| `dotnet/Sigilune.Manifest` | .NET Framework 4.8 exe (`sigilune-manifest.exe`) | ClickOnce / VSTO マニフェストの XML 署名・参照更新・検証。`sigilune sign-manifest` / `verify-manifest` から起動される |

クラウドとの HTTPS 通信は `ssign-core`（MIT, Le-Syl21/ssign）の公開関数 `auth::login` / `card::fetch` / `sign::request` / `client::client` を使う。`ssign-core` 自身の平文トークンキャッシュ（`CloudSession`）は使わない。

## 署名の流れ

1. `sigilune sign` が対象を確認する（存在・重複・`WinVerifyTrust` で未署名か。署名済みは `--replace`（上書き）か `--skip-signed`（有効な署名なら対象から外す。無効な署名は拒否）がなければ拒否。入れ子署名（`/as`）は検証が先頭の署名しか見ないため未提供）。
2. `session::acquire` でセッションを得る（下記）。署名者の CN をここで確定する。
3. `signtool sign /fd SHA256 /td SHA256 /tr <TSA> /dlib sigilune_dlib.dll <files>` を1回で実行する。
4. signtool（SignerSignEx3）が形式ごとに署名データを組み立て、認証属性のダイジェスト（SHA-256, 32バイト）を dlib へ渡す。
5. dlib が同じセッションを取得してクラウドに署名させ、RSA PKCS#1 v1.5 署名（big-endian）・署名者証明書・中間証明書を返す。
6. signtool が RFC 3161 タイムスタンプを付けて埋め込む。
7. `sigilune sign` が全ファイルを `WinVerifyTrust` で検証する（有効・署名者 CN 一致・タイムスタンプあり）。

## マニフェスト署名の流れ（ClickOnce / VSTO）

signtool はマニフェストの XML 署名を作れないため、MSBuild の `mansign2.cs`（MIT）を移植した補助ツールで署名する。

1. `sigilune sign-manifest` がセッションを得て、署名者証明書と発行元の中間証明書（同梱 DER から発行者一致で選ぶ）を一時フォルダーへ書き出す。補助ツールが同じセッションを使えるよう、起動前にミューテックスを手放す。
2. `sigilune-manifest.exe sign --sigilune <sigilune.exe> --cert ... --intermediate ... [--application <app>] <files>` を起動する。
3. 補助ツールは公開鍵だけを持つ `DelegatingRsa` を使い、mansign2 と同じ順序（既存署名の除去 → publicKeyToken 置換 → publisherIdentity 挿入 → Authenticode ライセンス署名 + RFC 3161 タイムスタンプ → 強名署名）で XML を組み立てる。RSA 署名が必要になるたびに `sigilune sign-hash --no-login <hex>` を呼び、返った署名を公開鍵で検証してから使う。
4. `--application` があれば先にアプリケーション マニフェストへ署名し、配置マニフェスト内の参照（size・DigestValue・publicKeyToken）を更新してから配置マニフェストへ署名する。
5. `verify` で検証する。System.Deployment の `SignedCmiManifest2.Verify` は成功時も TRUST_E_FAIL を残し、タイムスタンプ時刻を返さず、信頼された発行元ストアへの登録を前提にするため、同じ内部処理（強名署名・ライセンス署名・証明書・失効・タイムスタンプ・publisherIdentity）をリフレクションで個別に呼ぶ。信頼された発行元ストアへの登録は情報として表示するだけで合否に含めない。

- 公開鍵トークン・発行者鍵ハッシュは .NET Framework の `clr.dll` 内部関数でしか計算できないため、補助ツールは net48 を対象にする（Windows 10 1903 以降は標準搭載）。
- 署名アルゴリズムは rsa-sha256 だけ。タイムスタンプなしの署名は `--no-timestamp`（テスト用、CLI からは使わない）。
- 改行・空白は入力を保つ（`XmlTextReader` + `PreserveWhitespace`）。テスト鍵では `mage.exe -Sign` の出力とバイト単位で一致する（`tests/Test-ManifestSigning.ps1`、CI で実行）。

## セッションと秘密情報

- **登録情報**：資格情報マネージャーの汎用資格情報（既定名 `Sigilune/Certum SimplySign`、`SIGILUNE_CREDENTIAL` で変更）。UserName にメール、Blob に otpauth URI（Blob が空の資格情報は登録不正として扱う）。CI では `SIGILUNE_EMAIL` と `SIGILUNE_TOTP_URI` の環境変数を優先して使う（片方だけは設定ミスとして拒否）。GitHub Actions では各リポジトリの Environment `release`（ブランチ制限あり・承認者なし。`/vava` を離席中も完走させるため）の Secrets として渡す。複数ジョブが別マシンで同じ TOTP 時間枠を使うと後者が拒否されるため、署名は1ジョブにまとめるか直列化する。
- **セッションキャッシュ**：`%LOCALAPPDATA%\Sigilune\session.bin`（`SIGILUNE_HOME` で変更）。中身はトークン・カード番号・証明書 PEM の JSON を DPAPI（現在のユーザー、追加エントロピー `Sigilune.Session.v1`）で保護したもの。有効期間はログインから20分とし、残り120秒未満は使わない。
- **補助状態**：同フォルダーの `state.json` に、最後にログインへ使った TOTP の時間枠（`last_otp_step`）だけを保存する。秘密は含まない。
- **パッケージアプリ配下での注意**：MSIX パッケージのアプリ（例：Claude デスクトップ）から起動したプロセスでは `%LOCALAPPDATA%` への新規書込みが `Packages\<pkg>\LocalCache\Local` へ振り替えられ、通常の端末とキャッシュ・`state.json` が別になる。その場合は余分なログインが起こり得て、TOTP 時間枠の記録も別々になる（同じ枠を二重に使うとログインが拒否されるだけで、自動再試行はしない）。共有したいときは `SIGILUNE_HOME` で同じ実フォルダーを指定する。資格情報マネージャーは振替えの対象外で共通。
- **排他**：`Local\Sigilune.Session.<tag>` の名前付きミューテックスでキャッシュ確認からログイン・保存までを直列化する（`<tag>` は状態フォルダーの実体パスから決める。書き方の違い〔末尾の `\`・大文字小文字・`..`・ジャンクション〕や既定フォルダーの明示指定でも同じ排他になり、既定は旧版と同じ `default`）。並列に起動された署名プロセスはログイン1回を共有する。待機の上限は180秒。

## 不変条件

- 秘密値（otpauth URI・TOTP コード・トークン）を引数・標準出力・ログに出さない。`setup` は URI を非表示入力・標準入力・JSON ファイルからだけ受け取る。
- 同じ TOTP の時間枠を二度ログインに使わない。枠は送信前に記録し、残り5秒未満の枠は使わない。記録の枠が先にあって60秒を超えて待つ場合（PC の時計が戻された、または `state.json` の破損）は、記録を書き換えずロックを持ったまま待ち続けることもせず、理由を示して失敗する。
- ログイン失敗時に自動再試行しない（アカウントロック・不正検知を避ける）。
- dlib は SHA-256 の32バイトダイジェスト以外を `NTE_BAD_ALGID` で拒否する。パニックを FFI 境界の外へ出さず `E_FAIL` にする。
- dlib の出力メモリは `HeapAlloc(GetProcessHeap())`、証明書は所有権を移した `CERT_CONTEXT`（呼出し元が解放）。
- 同梱の中間証明書は署名者の発行者と一致したものだけをチェーン用ストアへ追加する。
- `ssign-core` は完全一致（`=0.1.8`）で固定する。上げるときは本番アカウントで exe と MSIX の署名・検証をやり直す。
- テスト用ローカル鍵バックエンドは dlib のメタデータ（`/dmdf`）で `local_key_pem` と `local_cert` を両方指定したときだけ使われる。
- リリース（`release.yml`）は `v1.2.3` 形式のタグの push でだけ起動する。利用者向けのメジャー版タグ（`v1`）は付け替えるため、`v*` では本番署名と公開が意図せず走る。タグとクレートの版が違えば止める。署名用 Secrets は Environment `release`（main と `v*` タグだけ許可）にだけ置く。

## 検証済みの事実（2026-11-13）

- テスト鍵で exe / msi / ps1 / msix を `/dlib` 経由で署名し、WinVerifyTrust が署名値を受理（ルート不信頼のみ）することを結合テストで確認。
- 本番証明書で exe / msix / ps1 / msi に署名し、`signtool verify /pa /all` と `Get-AuthenticodeSignature` で Valid・タイムスタンプありを確認。チェーンは Certum Trusted Network CA → CA 2 → Code Signing 2021 CA → 署名者。
- セッション破棄後に3プロセスを並列起動し、ログインが1回だけで全件成功することを確認。
- クラウドへ直接ログインしても、同じ PC の SimplySign Desktop の接続（鍵の利用）は維持された。
- 本番署名した exe と msix の署名データに、署名者と「Certum Code Signing 2021 CA」が埋め込まれていることを確認（チェーンを利用者側のストアに頼らない）。
- 本番証明書で VSTO アドインの `.dll.manifest` と `.vsto` に `sign-manifest` で署名し、publicKeyToken・issuerKeyHash がローカル証明書ストアでの署名（`mage` / MSBuild）と同一、Certum のタイムスタンプ付き、改ざんで検証失敗となることを確認。
- 未確認：Velopack `--signTemplate` 経由、`.cab` / `.cat` / `.dll` / `.appx`、signtool を直接呼んだ場合の dlib 内ログイン。

## 採用しなかった案

- **SimplySign Desktop の画面へ TOTP を自動入力する方式**：Windows 限定で UI の言語・版に弱く、配布に向かない。
- **PE などの署名データを自前で組み立てる方式（ssign 本体）**：MSIX などに対応できない。signtool に任せる `/dlib` 方式なら全形式に対応できる。
- **マニフェスト署名を Rust で自前実装する案**：publicKeyToken・issuerKeyHash・Authenticode ライセンスの計算を .NET Framework の内部実装と完全に一致させる必要があり、MSBuild の実装を移植した方が確実で、`mage.exe` との一致も検証できる。
- **MCP サーバーを本体にする案**：ビルドスクリプトから呼べず、任意ファイルへの署名窓口になるため。必要になれば CLI の上に状態確認だけの薄い層として追加する。
