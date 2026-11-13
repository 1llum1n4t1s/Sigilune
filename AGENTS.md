# AGENTS.md

Sigilune で作業するエージェント向けの運用ガイド。設計・不変条件は [DESIGN.md](DESIGN.md) を正本とし、変更前に読む。

## 概要

Certum SimplySign のクラウド証明書で、signtool が扱える全形式に Authenticode 署名する Rust 製 CLI（`sigilune.exe`）と signtool `/dlib`（`sigilune_dlib.dll`）。Windows x64 専用。公開 OSS（MIT）。

## コマンド

```powershell
cargo build                     # デバッグ
cargo build --release           # 配布用（target\release\sigilune.exe と sigilune_dlib.dll）
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked             # 単体テスト＋テスト鍵での signtool /dlib 結合テスト（exe/msi/ps1/msix）

# マニフェスト署名の補助ツール（net48。.NET SDK だけでビルドできる）と mage.exe との一致テスト
dotnet build dotnet/Sigilune.Manifest/Sigilune.Manifest.csproj -c Release -o <出力先>
pwsh -File tests/Test-ManifestSigning.ps1 -Tool <出力先>\sigilune-manifest.exe -WorkDirectory <空の作業フォルダー>
```

- toolchain は `rust-toolchain.toml` で固定する。
- 結合テストは Windows SDK の `signtool.exe` / `makeappx.exe` を使い、なければスキップする。
- Git Bash から signtool を直接呼ぶときは `MSYS2_ARG_CONV_EXCL='*'` を付ける（`/fd` などがパスに変換されるため）。

## 実署名での確認（本番アカウント）

本番の証明書・非公式プロトコルを使うため、確認は最小限にする。

- ログインは1回ずつ行い、失敗したら再試行せず原因を報告する。
- 署名対象は作業用の一時フォルダーの複製だけにする。
- 確認は `sigilune sign` の検証結果に加え、`signtool verify /pa /all /v` と `Get-AuthenticodeSignature` で独立に行う（Valid・署名者・タイムスタンプ）。
- otpauth URI・TOTP コード・トークン・メールアドレスを出力や記録へ残さない。

## 変更時の注意

- 利用者向けの出力・README は英語、コードコメントは日本語で書く。
- `ssign-core` の版を上げるときは、本番アカウントで exe と MSIX の署名・独立検証をやり直してから固定を更新する。Dependabot（`.github/dependabot.yml`）は `ssign-core` と、版を揃える `reqwest` をグループに入れず単独 PR にしているので、この2つの PR は検証前に取り込まない。
- dlib の FFI 契約（`HeapAlloc(GetProcessHeap())`、証明書の所有権移譲、SHA-256 のみ、パニック捕捉）を崩さない。
- セッションの排他・TOTP 時間枠の記録・自動再試行なしを崩さない（並列署名と Certum のコード再利用拒否に対応するため）。
- `dotnet/Sigilune.Manifest` は MSBuild の `mansign2.cs`（MIT）の移植。署名 XML の組み立て順序と改行の扱いを変えると `mage.exe` との一致テストが崩れるので、変えるときはテストで確認する。補助ツールの版は release.yml が Cargo の版を渡す。
- MCP・別 OS 対応・ARM64 は未実装。追加するときは DESIGN.md を更新する。
