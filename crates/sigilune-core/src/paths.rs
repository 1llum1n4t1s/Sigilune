//! Sigilune が使うローカルの保存先。
//!
//! 既定は `%LOCALAPPDATA%\Sigilune`。テストや複数環境の分離のため、
//! 環境変数 `SIGILUNE_HOME` で絶対パスを指定できる。

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

/// 状態フォルダー（なければ作成する）。
pub fn state_dir() -> Result<PathBuf> {
    let dir = match std::env::var_os("SIGILUNE_HOME") {
        Some(home) => {
            let p = PathBuf::from(home);
            if !p.is_absolute() {
                bail!("SIGILUNE_HOME must be an absolute path");
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

/// DPAPI で保護したセッションキャッシュ。
pub fn session_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("session.bin"))
}

/// 秘密を含まない補助状態（最後に使った TOTP の時間枠など）。
pub fn state_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("state.json"))
}

/// 名前付きミューテックス名の接尾辞。`SIGILUNE_HOME` ごとに分け、テストが本番と干渉しないようにする。
pub fn instance_tag() -> String {
    match std::env::var_os("SIGILUNE_HOME") {
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
