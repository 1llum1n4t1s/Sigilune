# Changelog

## 1.0.0 - 2026-11-13

### 追加

- Certum SimplySign のクラウド証明書で、signtool が扱う形式（exe・dll・msi・msix・ps1 など）へ署名する `sigilune` CLI と signtool 用 DLL（`sigilune_dlib.dll`）を初めて公開。SimplySign Desktop とワンタイムコードの手入力は不要。
- `setup` / `login` / `status` / `logout` / `sign` / `verify` / `cert` コマンド。署名後に有効性・署名者・タイムスタンプを検証する。
- アカウントと TOTP 登録情報は Windows 資格情報マネージャーに保存し、CI 向けに `SIGILUNE_EMAIL` / `SIGILUNE_TOTP_URI` 環境変数でも渡せる。
- 複数プロセスからの同時署名でもログインを1回に共有し、同じ TOTP コードを二度使わない。
- ワンライナーの導入スクリプト（`install.ps1`、SHA-256 と署名者を確認して導入）と、GitHub Actions 用のセットアップアクション（`uses: 1llum1n4t1s/Sigilune@v1`）。
