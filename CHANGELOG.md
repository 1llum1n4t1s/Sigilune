# Changelog

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
