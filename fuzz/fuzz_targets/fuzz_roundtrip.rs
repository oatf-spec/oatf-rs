#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    let doc = match oatf::parse(&s) {
        Ok(d) => d,
        Err(_) => return,
    };

    let normalized = oatf::normalize(doc);

    let yaml = match oatf::serialize(&normalized) {
        Ok(y) => y,
        Err(_) => return,
    };

    // If we can serialize a normalized document, we must be able to parse it back.
    if oatf::parse(&yaml).is_err() {
        panic!(
            "Roundtrip failure: serialize produced YAML that cannot be re-parsed.\n\
             Input (lossy): {:?}\n\
             Serialized YAML:\n{}",
            s.get(..200).unwrap_or(&s),
            yaml.get(..500).unwrap_or(&yaml),
        );
    }
});
