#![no_main]

use libfuzzer_sys::fuzz_target;
use oatf::primitives::{resolve_simple_path, resolve_wildcard_path};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use the first byte to determine the split point between path and JSON value.
    let split = data[0] as usize % data.len().max(1);
    let (path_bytes, value_bytes) = data.split_at(split.min(data.len()));

    let path = String::from_utf8_lossy(path_bytes);

    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(value_bytes) {
        let _ = resolve_simple_path(&path, &value);
        let _ = resolve_wildcard_path(&path, &value);
    }
});
