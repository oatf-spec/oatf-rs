use oatf::primitives::{evaluate_predicate, evaluate_condition};
use oatf::types::{Condition, MatchCondition, MatchEntry};
use proptest::prelude::*;
use serde_json::{json, Value};
use std::collections::HashMap;

fn empty_match_condition() -> MatchCondition {
    MatchCondition {
        contains: None,
        starts_with: None,
        ends_with: None,
        regex: None,
        any_of: None,
        gt: None,
        lt: None,
        gte: None,
        lte: None,
        exists: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Empty predicate always returns true
    #[test]
    fn empty_predicate_is_true(n in -100i64..100) {
        let predicate = HashMap::new();
        let value = json!(n);
        prop_assert!(evaluate_predicate(&predicate, &value));
    }

    // Single-path scalar equality: existing path with matching value → true
    #[test]
    fn scalar_equality_existing_path(
        key in "[a-z]{1,6}",
        val in -100i64..100,
    ) {
        let mut obj = serde_json::Map::new();
        obj.insert(key.clone(), json!(val));
        let value = Value::Object(obj);

        let mut predicate = HashMap::new();
        predicate.insert(key, MatchEntry::Scalar(json!(val)));
        prop_assert!(evaluate_predicate(&predicate, &value));
    }

    // Nonexistent path returns false (not panic)
    #[test]
    fn nonexistent_path_returns_false(
        key in "[a-z]{1,6}",
        val in -100i64..100,
    ) {
        let value = json!({"other_key": val});
        let mut predicate = HashMap::new();
        predicate.insert(key.clone(), MatchEntry::Scalar(json!(val)));
        // If key happens to be "other_key", it will match; otherwise false
        let expected = key == "other_key";
        prop_assert_eq!(evaluate_predicate(&predicate, &value), expected);
    }

    // exists: true on existing path → true
    #[test]
    fn exists_true_existing(
        key in "[a-z]{1,6}",
        val in -100i64..100,
    ) {
        let mut obj = serde_json::Map::new();
        obj.insert(key.clone(), json!(val));
        let value = Value::Object(obj);

        let mut predicate = HashMap::new();
        predicate.insert(key, MatchEntry::Condition(MatchCondition {
            exists: Some(true),
            ..empty_match_condition()
        }));
        prop_assert!(evaluate_predicate(&predicate, &value));
    }

    // exists: false on missing path → true
    #[test]
    fn exists_false_missing(
        key in "[a-z]{1,6}",
    ) {
        let value = json!({});
        let mut predicate = HashMap::new();
        predicate.insert(key, MatchEntry::Condition(MatchCondition {
            exists: Some(false),
            ..empty_match_condition()
        }));
        prop_assert!(evaluate_predicate(&predicate, &value));
    }

    // exists: true on missing path → false
    #[test]
    fn exists_true_missing(
        key in "[a-z]{1,6}",
    ) {
        let value = json!({});
        let mut predicate = HashMap::new();
        predicate.insert(key, MatchEntry::Condition(MatchCondition {
            exists: Some(true),
            ..empty_match_condition()
        }));
        prop_assert!(!evaluate_predicate(&predicate, &value));
    }

    // exists: false on existing path → false
    #[test]
    fn exists_false_existing(
        key in "[a-z]{1,6}",
        val in -100i64..100,
    ) {
        let mut obj = serde_json::Map::new();
        obj.insert(key.clone(), json!(val));
        let value = Value::Object(obj);

        let mut predicate = HashMap::new();
        predicate.insert(key, MatchEntry::Condition(MatchCondition {
            exists: Some(false),
            ..empty_match_condition()
        }));
        prop_assert!(!evaluate_predicate(&predicate, &value));
    }

    // Multi-entry AND: two entries that both match → true, flip one → false
    #[test]
    fn multi_entry_and_logic(a in -50i64..50, b in -50i64..50) {
        let value = json!({"x": a, "y": b});

        // Both match
        let mut pred_match = HashMap::new();
        pred_match.insert("x".to_string(), MatchEntry::Scalar(json!(a)));
        pred_match.insert("y".to_string(), MatchEntry::Scalar(json!(b)));
        prop_assert!(evaluate_predicate(&pred_match, &value));

        // One wrong → false
        let mut pred_wrong = HashMap::new();
        pred_wrong.insert("x".to_string(), MatchEntry::Scalar(json!(a)));
        pred_wrong.insert("y".to_string(), MatchEntry::Scalar(json!(b + 1)));
        let expected = b == b + 1; // overflow wrap — always false for i64 in this range
        prop_assert_eq!(evaluate_predicate(&pred_wrong, &value), expected);
    }

    // Single-entry predicate with condition is consistent with evaluate_condition
    #[test]
    fn predicate_condition_consistent_with_evaluate_condition(
        val in "[a-zA-Z0-9]{1,20}",
        substring in "[a-zA-Z0-9]{0,5}",
    ) {
        let json_value = json!({"field": val.clone()});
        let cond = MatchCondition {
            contains: Some(substring.clone()),
            ..empty_match_condition()
        };
        let mut predicate = HashMap::new();
        predicate.insert("field".to_string(), MatchEntry::Condition(cond.clone()));

        let cond_result = evaluate_condition(
            &Condition::Operators(cond),
            &Value::String(val),
        );
        let pred_result = evaluate_predicate(&predicate, &json_value);
        prop_assert_eq!(pred_result, cond_result);
    }
}
