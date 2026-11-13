//! Win32 API へ渡す UTF-16 文字列の補助。

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

/// NUL 終端付きの UTF-16 へ変換する。
pub(crate) fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// NUL 終端の UTF-16 ポインタを String へ変換する（null は空文字）。
///
/// # Safety
/// `p` は null か、NUL 終端された有効な UTF-16 列を指すこと。
pub(crate) unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: 呼出し元が NUL 終端を保証する。
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}
