#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    if let Ok(doc) = oatf::parse(&s) {
        let _ = oatf::normalize(doc);
    }
});
