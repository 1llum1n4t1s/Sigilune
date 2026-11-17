# Changelog

## Unreleased

## 1.1.4 - 2026-11-18

### 修正

- `install.ps1` がユーザー PATH を書き戻すとき、既存の `%VAR%` 参照を導入時点の値に固定し、値の種別を REG_EXPAND_SZ から REG_SZ に変えていた問題を直した。レジストリを展開せずに読み、元の値種別を保って追記し、書き込み後に環境変更を通知する。PATH を更新できない場合も警告だけで導入は成功とする。
- `install.ps1` を ASCII のみにした（保存して Windows PowerShell 5.1 で実行すると、BOM なし UTF-8 の日本語コメントが改行を巻き込んで壊れ得るため）。

## 1.1.3 - 2026-11-16

### 変更

- 配布を GitHub Release から Cloudflare R2（`https://sigilune.kagayoi.com`）へ移した。タグと GitHub Release は使わず、`release/<version>` ブランチの push で署名・配信する。`install.ps1` は R2 の `latest.json`（または `-Version` 指定の版付き zip と `.sha256`）から取り、SHA-256 と署名者の照合は従来どおり行う。`-BaseUrl` を追加。
- 同梱の `action.yml` は、`uses: …@<コミット SHA>` で参照したチェックアウトの `Cargo.toml` の版を入れるようにした（SHA 固定がそのまま版固定になる）。`github.action_ref` による「最新を入れる」判定は廃止。`inputs.version` の指定は従来どおり優先する。
- 移動タグ `v1` の付け替えを廃止した。利用側は `@v1` ではなくコミット SHA で参照する。

## 1.1.2 - 2026-11-15

### 修正

- `SIGILUNE_HOME` の書き方（末尾の `\`、大文字小文字、`..`、ジャンクションなど）だけが違うと、同じ保存先でもログインの排他が効かず、並列に起動した署名で同じワンタイムコードが送られて拒否されることがあった問題を修正。保存先の実体で排他するようにした。
- PC の時計が戻された場合などに、最後に使ったワンタイムコードの時間枠が今より先になっていると、ログインが終わらずに待ち続けた問題を修正。待つのは60秒までにし、それを超えるときは理由を示して失敗する（同じワンタイムコードは再利用しない）。
- 資格情報マネージャーに同じ名前の空の資格情報があると、読み出しで不正なメモリ操作をするおそれがあった問題を修正。登録が不正というエラーにする。

## 1.1.1 - 2026-11-13

### 変更

- 配布バイナリを Rust 1.100.0 と更新した依存（rsa 0.10 など）でビルド。コマンド・出力・署名の動作に変更はない。

## 1.1.0 - 2026-11-13

### 追加

- ClickOnce / VSTO マニフェスト（`.manifest`・`.application`・`.vsto`）へクラウド証明書で署名する `sign-manifest` と、検証する `verify-manifest`。アプリケーション マニフェストへの参照（サイズ・ダイジェスト・公開鍵トークン）を更新してから配置マニフェストへ署名し、RFC 3161 タイムスタンプと中間証明書を埋め込む。テスト鍵では `mage.exe -Sign` とバイト単位で同じ出力になる。
- 署名処理を担う補助ツール `sigilune-manifest.exe`（.NET Framework 4.8、MSBuild の署名処理を移植）を配布 zip に同梱。導入スクリプトとセットアップアクションも同梱物を導入する。
- `sign --skip-signed`：有効な署名が既にあるファイル（Velopack の署名テンプレートが渡す Microsoft 製 DLL など）を拒否せずそのまま残す。無効な署名は従来どおり拒否する。
- SHA-256 ダイジェスト1件に署名する `sign-hash` と、`cert --intermediate-out`（発行元の中間証明書を書き出す）。

## 1.0.0 - 2026-11-13

### 追加

- Certum SimplySign のクラウド証明書で、signtool が扱う形式（exe・dll・msi・msix・ps1 など）へ署名する `sigilune` CLI と signtool 用 DLL（`sigilune_dlib.dll`）を初めて公開。SimplySign Desktop とワンタイムコードの手入力は不要。
- `setup` / `login` / `status` / `logout` / `sign` / `verify` / `cert` コマンド。署名後に有効性・署名者・タイムスタンプを検証する。
- アカウントと TOTP 登録情報は Windows 資格情報マネージャーに保存し、CI 向けに `SIGILUNE_EMAIL` / `SIGILUNE_TOTP_URI` 環境変数でも渡せる。
- 複数プロセスからの同時署名でもログインを1回に共有し、同じ TOTP コードを二度使わない。
- ワンライナーの導入スクリプト（`install.ps1`、SHA-256 と署名者を確認して導入）と、GitHub Actions 用のセットアップアクション（`uses: 1llum1n4t1s/Sigilune@v1`）。
