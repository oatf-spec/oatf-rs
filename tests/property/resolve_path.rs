use oatf::primitives::{resolve_simple_path, resolve_wildcard_path};
use proptest::prelude::*;
use serde_json::{Value, json};

/// Strategy for arbitrary JSON values nested up to `depth` levels.
fn arb_json(depth: u32) -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|i| json!(i)),
        "[a-z]{1,8}".prop_map(|s| Value::String(s)),
    ];

    leaf.prop_recursive(depth, 64, 8, |inner| {
        prop_oneof![
            // Array of values
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            // Object with snake_case keys
            prop::collection::vec(("[a-z][a-z0-9]{0,5}", inner), 1..5,).prop_map(|pairs| {
                let map: serde_json::Map<String, Value> = pairs.into_iter().collect();
                Value::Object(map)
            }),
        ]
    })
}

/// Extract all valid dot-paths from a JSON value (objects only, up to max_depth).
fn extract_paths(value: &Value, prefix: &str, paths: &mut Vec<String>, max_depth: u32) {
    if max_depth == 0 {
        return;
    }
    if let Some(obj) = value.as_object() {
        for (key, child) in obj {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", prefix, key)
            };
            paths.push(path.clone());
            extract_paths(child, &path, paths, max_depth - 1);
        }
    }
}

/// Extract wildcard paths — for arrays, generate field[*] paths.
fn extract_wildcard_paths(value: &Value, prefix: &str, paths: &mut Vec<String>, max_depth: u32) {
    if max_depth == 0 {
        return;
    }
    if let Some(obj) = value.as_object() {
        for (key, child) in obj {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", prefix, key)
            };
            paths.push(path.clone());
            if child.is_array() {
                let wildcard_path = format!("{}[*]", path);
                paths.push(wildcard_path.clone());
                // Recurse into array elements for deeper paths
                if let Some(arr) = child.as_array() {
                    if let Some(first) = arr.first() {
                        extract_wildcard_paths(first, &wildcard_path, paths, max_depth - 1);
                    }
                }
            } else {
                extract_wildcard_paths(child, &path, paths, max_depth - 1);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn empty_path_returns_root_simple(value in arb_json(3)) {
        let result = resolve_simple_path("", &value);
        prop_assert_eq!(result, Some(value));
    }

    #[test]
    fn empty_path_returns_root_wildcard(value in arb_json(3)) {
        let result = resolve_wildcard_path("", &value);
        prop_assert_eq!(result, vec![value]);
    }

    #[test]
    fn valid_path_returns_nonempty(value in arb_json(3)) {
        let mut paths = Vec::new();
        extract_paths(&value, "", &mut paths, 4);
        if !paths.is_empty() {
            let path = &paths[0];
            let result = resolve_simple_path(path, &value);
            prop_assert!(result.is_some(), "resolve_simple_path({:?}) returned None on value {:?}", path, value);
        }
    }

    #[test]
    fn wildcard_valid_path_returns_nonempty(value in arb_json(3)) {
        let mut paths = Vec::new();
        extract_wildcard_paths(&value, "", &mut paths, 4);
        // Only test non-wildcard paths (wildcard paths may return empty if array is empty)
        let simple_paths: Vec<_> = paths.iter().filter(|p| !p.contains("[*]")).collect();
        if !simple_paths.is_empty() {
            let path = simple_paths[0];
            let result = resolve_wildcard_path(path, &value);
            prop_assert!(!result.is_empty(), "resolve_wildcard_path({:?}) returned empty on value {:?}", path, value);
        }
    }

    #[test]
    fn wildcard_on_array_returns_n_results(
        n in 1..8usize,
        elem in arb_json(1),
    ) {
        let arr: Vec<Value> = (0..n).map(|_| elem.clone()).collect();
        let obj = json!({"items": arr});
        let result = resolve_wildcard_path("items[*]", &obj);
        prop_assert_eq!(result.len(), n, "Expected {} results, got {}", n, result.len());
    }

    #[test]
    fn simple_path_never_panics(
        path in "\\PC{0,30}",
        value in arb_json(2),
    ) {
        let _ = resolve_simple_path(&path, &value);
    }

    #[test]
    fn wildcard_path_never_panics(
        path in "\\PC{0,30}",
        value in arb_json(2),
    ) {
        let _ = resolve_wildcard_path(&path, &value);
    }
}
