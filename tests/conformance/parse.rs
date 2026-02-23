use oatf::parse::parse;
use std::fs;
use std::path::PathBuf;

fn conformance_dir() -> PathBuf {
    std::env::var("OATF_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("spec/conformance"))
}

#[test]
fn parse_valid_fixtures() {
    let valid_dir = conformance_dir().join("parse/valid");
    if !valid_dir.exists() {
        eprintln!("Skipping parse valid tests: {:?} not found", valid_dir);
        return;
    }

    for entry in fs::read_dir(&valid_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains(".meta.")
        {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        let result = parse(&content);
        assert!(
            result.is_ok(),
            "Expected valid parse for {:?}, got error: {:?}",
            path.file_name().unwrap(),
            result.err()
        );
    }
}

#[test]
fn parse_invalid_fixtures() {
    let invalid_dir = conformance_dir().join("parse/invalid");
    if !invalid_dir.exists() {
        eprintln!("Skipping parse invalid tests: {:?} not found", invalid_dir);
        return;
    }

    for entry in fs::read_dir(&invalid_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        if path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains(".meta.")
        {
            continue;
        }

        let content = fs::read_to_string(&path).unwrap();
        let result = parse(&content);
        assert!(
            result.is_err(),
            "Expected parse error for {:?}, but parsed successfully",
            path.file_name().unwrap(),
        );
    }
}
