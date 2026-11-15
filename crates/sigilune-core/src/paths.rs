//! Sigilune が使うローカルの保存先。
//!
//! 既定は `%LOCALAPPDATA%\Sigilune`。テストや複数環境の分離のため、
//! 環境変数 `SIGILUNE_HOME` で絶対パスを指定できる。

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

/// 保存先を上書きする環境変数。保存先（`state_dir`）とミューテックス名（`instance_tag`）は
/// 同じ値から決まる必要があるため、名前を1か所で持つ。
const ENV_HOME: &str = "SIGILUNE_HOME";

/// 状態フォルダー（なければ作成する）。
fn state_dir() -> Result<PathBuf> {
    let dir = match std::env::var_os(ENV_HOME) {
        Some(home) => {
            let p = PathBuf::from(home);
            if !p.is_absolute() {
                bail!("{ENV_HOME} must be an absolute path");
            }
            p
        }
        None => {
            let base = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?;
            PathBuf::from(base).join("Sigilune")
        }
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// 環境変数でファイルが指定されていればそのパスを返す（未指定は `None`、ファイルでなければエラー）。
/// `SIGILUNE_SIGNTOOL` / `SIGILUNE_DLIB` / `SIGILUNE_MANIFEST_TOOL` の上書き指定で共通に使う。
pub(crate) fn file_from_env(var: &str) -> Result<Option<PathBuf>> {
    let Some(p) = std::env::var_os(var) else {
        return Ok(None);
    };
    let p = PathBuf::from(p);
    if !p.is_file() {
        bail!("{var} does not point to a file: {}", p.display());
    }
    Ok(Some(p))
}

/// 環境変数の指定、なければ実行中の exe（sigilune.exe）と同じフォルダーにある同梱ファイル。
/// `missing_hint` は同梱ファイルが見つからないときのメッセージの末尾へ付ける補足（不要なら空文字）。
pub(crate) fn env_or_beside_exe(var: &str, file_name: &str, missing_hint: &str) -> Result<PathBuf> {
    if let Some(p) = file_from_env(var)? {
        return Ok(p);
    }
    let exe = std::env::current_exe().context("locating sigilune.exe")?;
    let file = exe.with_file_name(file_name);
    if !file.is_file() {
        bail!(
            "{file_name} was not found next to {}{missing_hint}",
            exe.display()
        );
    }
    Ok(file)
}

/// DPAPI で保護したセッションキャッシュ。
pub(crate) fn session_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("session.bin"))
}

/// 秘密を含まない補助状態（最後に使った TOTP の時間枠など）。
pub(crate) fn state_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("state.json"))
}

/// 名前付きミューテックス名の接尾辞。`SIGILUNE_HOME` ごとに分け、テストが本番と干渉しないようにする。
pub(crate) fn instance_tag() -> String {
    match std::env::var_os(ENV_HOME) {
        None => "default".into(),
        Some(home) => {
            // パス文字列を単純なハッシュへ縮め、ミューテックス名に使えない文字を避ける。
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for b in home.to_string_lossy().to_lowercase().bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            format!("{h:016x}")
        }
    }
}
