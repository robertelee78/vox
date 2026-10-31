//! Narrow safe wrappers around the two Foundation filesystem operations used by the updater.

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, CString, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};

    extern "C" {
        fn vox_replacement_directory(
            path: *const std::ffi::c_char,
            result: *mut std::ffi::c_char,
            result_capacity: usize,
            error: *mut std::ffi::c_char,
            error_capacity: usize,
        ) -> i32;
        fn vox_remove_item(
            path: *const std::ffi::c_char,
            error: *mut std::ffi::c_char,
            error_capacity: usize,
        ) -> i32;
    }

    fn input(path: &Path) -> Result<CString, String> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| "path contains a NUL byte".into())
    }

    fn message(buffer: &[u8]) -> String {
        let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        String::from_utf8_lossy(&buffer[..end]).into_owned()
    }

    /// Create a Foundation replacement directory on the volume containing `path`.
    pub fn replacement_directory(path: &Path) -> Result<PathBuf, String> {
        let path = input(path)?;
        let mut result = [0u8; 4096];
        let mut error = [0u8; 4096];
        // SAFETY: all pointers refer to live, non-overlapping buffers for this synchronous call;
        // their capacities are passed verbatim. The C side NUL-terminates output before success.
        let ok = unsafe {
            vox_replacement_directory(
                path.as_ptr(),
                result.as_mut_ptr().cast(),
                result.len(),
                error.as_mut_ptr().cast(),
                error.len(),
            )
        };
        if ok == 0 {
            return Err(message(&error));
        }
        let bytes = CStr::from_bytes_until_nul(&result)
            .map_err(|e| e.to_string())?
            .to_bytes();
        Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }

    /// Remove exactly `path` with Foundation and retain the native error chain on refusal.
    pub fn remove_item(path: &Path) -> Result<(), String> {
        let path = input(path)?;
        let mut error = [0u8; 4096];
        // SAFETY: path and writable error buffer remain alive throughout the synchronous call;
        // the C implementation receives the exact buffer capacity and retains no pointers.
        let ok = unsafe { vox_remove_item(path.as_ptr(), error.as_mut_ptr().cast(), error.len()) };
        if ok == 0 {
            Err(message(&error))
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::{remove_item, replacement_directory};
