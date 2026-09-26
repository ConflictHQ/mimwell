//! Versioned C ABI. Caller-owned output avoids allocator/ownership ambiguity.
use crate::{INPUT_CAP, OUTPUT_CAP, classify_json};
use std::{path::Path, ptr, slice, str};

const PATH_CAP: usize = 4096;

#[unsafe(no_mangle)]
pub extern "C" fn brain_classifier_output_capacity_v1() -> usize {
    OUTPUT_CAP
}

/// Evaluate the existing JSON classifier contract without a child process.
///
/// Returns 0 on success, 1 for ABI admission errors, 2 for classifier rejection,
/// and 3 for a caught Rust unwind. Rejections never return partial predictions.
/// On ABI rejection `output_len` is zero. Other errors contain a bounded JSON
/// category. The buffer must hold OUTPUT_CAP bytes before any inference starts:
/// sizing/retry calls must not accidentally execute the model twice.
///
/// # Safety
/// Nonempty input pointers must reference readable initialized bytes for their
/// lengths. `output` must reference OUTPUT_CAP writable bytes and `output_len`
/// one writable usize; neither may overlap each other or any input. All memory
/// must remain valid throughout the synchronous call. Null pointers are rejected.
/// These checks cannot validate dangling pointers supplied by an unsafe caller.
/// Caught unwinds still invoke the embedding process's panic hook; aborts and
/// invalid foreign memory are not recoverable. No process-wide hook is installed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn brain_classifier_classify_v1(
    bundle_path: *const u8,
    path_len: usize,
    expected_sha256: *const u8,
    pin_len: usize,
    request: *const u8,
    request_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if output_len.is_null() {
        return 1;
    }
    // SAFETY: the caller promises a valid writable output_len.
    unsafe { *output_len = 0 };
    if bundle_path.is_null()
        || expected_sha256.is_null()
        || request.is_null()
        || output.is_null()
        || !(1..=PATH_CAP).contains(&path_len)
        || pin_len != 64
        || request_len > INPUT_CAP
        || output_capacity < OUTPUT_CAP
    {
        return 1;
    }
    let result = std::panic::catch_unwind(|| {
        // SAFETY: caller promises readable inputs; lengths were capped above.
        let (path, pin, raw) = unsafe {
            (
                slice::from_raw_parts(bundle_path, path_len),
                slice::from_raw_parts(expected_sha256, pin_len),
                slice::from_raw_parts(request, request_len),
            )
        };
        let path = str::from_utf8(path).map_err(|_| "invalid-bundle-path")?;
        let pin = str::from_utf8(pin).map_err(|_| "invalid-pin-or-input-budget")?;
        classify_json(Path::new(path), pin, raw)
    });
    let (status, bytes) = match result {
        Ok(Ok(bytes)) => (0, bytes),
        Ok(Err(category)) => (2, format!("{{\"error\":\"{category}\"}}").into_bytes()),
        Err(_) => (3, b"{\"error\":\"model-execution-failed\"}".to_vec()),
    };
    // Every successful/error result is capped below the pre-admitted buffer size.
    if bytes.len() > OUTPUT_CAP {
        return 3;
    }
    // SAFETY: caller supplies a writable, non-overlapping buffer with capacity.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        *output_len = bytes.len();
    }
    status
}
