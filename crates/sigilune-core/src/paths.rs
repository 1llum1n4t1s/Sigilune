//! Sigilune が使うローカルの保存先。
//!
//! 既定は `%LOCALAPPDATA%\Sigilune`。テストや複数環境の分離のため、
//! 環境変数 `SIGILUNE_HOME` で絶対パスを指定できる。

use anyhow::{Context, Result, bail};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// 保存先を上書きする環境変数。保存先（`state_dir`）とミューテックス名（`instance_tag`）は
/// 同じ値から決まる必要があるため、名前を1か所で持つ。
const ENV_HOME: &str = "SIGILUNE_HOME";

/// 状態フォルダー（なければ作成する）。
fn state_dir() -> Result<PathBuf> {
    resolve_home(std::env::var_os(ENV_HOME).as_deref())
}

/// `SIGILUNE_HOME` の値（未指定は `None`）から状態フォルダーを決め、なければ作成する。
fn resolve_home(home: Option<&OsStr>) -> Result<PathBuf> {
    let dir = match home {
        Some(home) => {
            let p = PathBuf::from(home);
            if !p.is_absolute() {
                bail!("{ENV_HOME} must be an absolute path");
            }
            p
        }
        None => default_dir()?,
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// 既定の状態フォルダー（`%LOCALAPPDATA%\Sigilune`）。
fn default_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(base).join("Sigilune"))
}

/// 同じフォルダーを指す書き方の違い（大文字小文字・末尾の `\`・`.`・ジャンクション）を吸収した実体パス。
/// 解決できなければ（権限など）書かれたパスのまま使う。
fn real_path(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
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

/// 名前付きミューテックス名の接尾辞。状態フォルダーごとに分け、テストが本番と干渉しないようにする。
///
/// 排他はキャッシュと TOTP 時間枠の記録（同じフォルダーのファイル）を守るためのものなので、
/// `SIGILUNE_HOME` の文字列ではなく、指しているフォルダーの実体で決める。書き方だけが違う指定や、
/// 既定のフォルダーを明示した指定でも同じミューテックスになる。
pub(crate) fn instance_tag() -> Result<String> {
    instance_tag_for(std::env::var_os(ENV_HOME).as_deref())
}

fn instance_tag_for(home: Option<&OsStr>) -> Result<String> {
    // 未指定は既定のフォルダー。旧版と同じ名前（"default"）を保ち、混在しても排他が効くようにする。
    let Some(home) = home else {
        return Ok("default".into());
    };
    let dir = real_path(&resolve_home(Some(home))?);
    if default_dir().is_ok_and(|d| real_path(&d) == dir) {
        return Ok("default".into());
    }
    // パス文字列を単純なハッシュへ縮め、ミューテックス名に使えない文字を避ける。
    // Windows のパスは大文字小文字を区別しないため小文字にそろえる。実体パスに付く `\\?\` は外し、
    // 正規の書き方（例 `D:\work\sigilune`）で指定した旧版のプロセスと同じ名前になるようにする。
    let text = dir.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.to_lowercase().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    Ok(format!("{h:016x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_folder_shares_one_tag_whatever_the_spelling() {
        // 既存のフォルダー（このクレート）を使い、テストで新しいフォルダーを作らない。
        let dir = env!("CARGO_MANIFEST_DIR").replace('/', "\\");
        let tag = |s: &str| instance_tag_for(Some(OsStr::new(s))).unwrap();
        let base = tag(&dir);
        assert_eq!(tag(&format!("{dir}\\")), base);
        assert_eq!(tag(&dir.to_uppercase()), base);
        assert_eq!(tag(&format!("{dir}\\src\\..")), base);
        assert_eq!(tag(&format!("\\\\?\\{dir}")), base);
        assert_ne!(tag(&format!("{dir}\\src")), base);
        assert_eq!(instance_tag_for(None).unwrap(), "default");
        assert!(instance_tag_for(Some(OsStr::new("relative\\dir"))).is_err());
    }
}
