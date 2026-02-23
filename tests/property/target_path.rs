use oatf::primitives::{resolve_simple_path, resolve_wildcard_path};
use proptest::prelude::*;
use serde_json::{json, Value};

/// Strategy for valid dot-separated paths.
fn arb_dot_path() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z][a-z0-9]{0,5}", 1..5)
        .prop_map(|parts| parts.join("."))
}

/// Build a nested object from a dot-path with a leaf value.
fn build_nested(path: &str, leaf: Value) -> Value {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = leaf;
    for part in parts.iter().rev() {
        let mut obj = serde_json::Map::new();
        obj.insert(part.to_string(), current);
        current = Value::Object(obj);
    }
    current
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // resolve_simple_path on a constructed nested object returns the leaf
    #[test]
    fn simple_path_round_trips(
        path in arb_dot_path(),
        leaf_val in -100i64..100,
    ) {
        let leaf = json!(leaf_val);
        let nested = build_nested(&path, leaf.clone());
        let result = resolve_simple_path(&path, &nested);
        prop_assert_eq!(result, Some(leaf),
            "resolve_simple_path({:?}) on constructed value failed", path);
    }

    // resolve_wildcard_path on a non-wildcard path should behave like simple path
    #[test]
    fn wildcard_without_star_equals_simple(
        path in arb_dot_path(),
        leaf_val in -100i64..100,
    ) {
        let leaf = json!(leaf_val);
        let nested = build_nested(&path, leaf.clone());
        let simple = resolve_simple_path(&path, &nested);
        let wildcard = resolve_wildcard_path(&path, &nested);
        match simple {
            Some(v) => prop_assert_eq!(wildcard, vec![v]),
            None => prop_assert!(wildcard.is_empty()),
        }
    }

    // Longer path than nesting depth returns None (not panic)
    #[test]
    fn deeper_path_returns_none(
        base_path in arb_dot_path(),
        extra_segment in "[a-z]{1,5}",
        leaf_val in -100i64..100,
    ) {
        let leaf = json!(leaf_val);
        let nested = build_nested(&base_path, leaf);
        let deeper = format!("{}.{}", base_path, extra_segment);
        let result = resolve_simple_path(&deeper, &nested);
        // The leaf is an integer, not an object, so deeper path should return None
        prop_assert_eq!(result, None);
    }

    // Wildcard on array yields correct count
    #[test]
    fn wildcard_array_count(
        field in "[a-z]{1,5}",
        n in 1..10usize,
        elem in -100i64..100,
    ) {
        let arr: Vec<Value> = (0..n).map(|_| json!(elem)).collect();
        let obj = json!({field.clone(): arr});
        let path = format!("{}[*]", field);
        let result = resolve_wildcard_path(&path, &obj);
        prop_assert_eq!(result.len(), n);
    }

    // Nested wildcard: field[*].subfield
    #[test]
    fn nested_wildcard_subfield(
        field in "[a-z]{1,5}",
        subfield in "[a-z]{1,5}",
        n in 1..6usize,
        val in -100i64..100,
    ) {
        let arr: Vec<Value> = (0..n)
            .map(|_| json!({subfield.clone(): val}))
            .collect();
        let obj = json!({field.clone(): arr});
        let path = format!("{}[*].{}", field, subfield);
        let result = resolve_wildcard_path(&path, &obj);
        prop_assert_eq!(result.len(), n,
            "Expected {} results for path {:?}, got {:?}", n, path, result);
        for v in &result {
            prop_assert_eq!(v, &json!(val));
        }
    }

    // Arbitrary path string never panics simple resolver
    #[test]
    fn arbitrary_path_simple_never_panics(
        path in "\\PC{0,30}",
    ) {
        let value = json!({"a": {"b": 1}});
        let _ = resolve_simple_path(&path, &value);
    }

    // Arbitrary path string never panics wildcard resolver
    #[test]
    fn arbitrary_path_wildcard_never_panics(
        path in "\\PC{0,30}",
    ) {
        let value = json!({"a": [1, 2, 3]});
        let _ = resolve_wildcard_path(&path, &value);
    }
}
