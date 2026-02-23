use oatf::primitives::{evaluate_condition, evaluate_match_condition};
use oatf::types::{Condition, MatchCondition};
use proptest::prelude::*;
use serde_json::{Value, json};

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

    // contains(substring, value) == value.contains(substring)
    #[test]
    fn contains_matches_std(
        value in "[a-zA-Z0-9 ]{0,50}",
        substring in "[a-zA-Z0-9]{0,10}",
    ) {
        let cond = MatchCondition {
            contains: Some(substring.clone()),
            ..empty_match_condition()
        };
        let json_value = Value::String(value.clone());
        let result = evaluate_match_condition(&cond, &json_value);
        prop_assert_eq!(result, value.contains(&substring),
            "contains({:?}, {:?}): expected {}, got {}", substring, value, value.contains(&substring), result);
    }

    // starts_with consistency
    #[test]
    fn starts_with_matches_std(
        value in "[a-zA-Z0-9]{0,20}",
        prefix in "[a-zA-Z0-9]{0,5}",
    ) {
        let cond = MatchCondition {
            starts_with: Some(prefix.clone()),
            ..empty_match_condition()
        };
        let json_value = Value::String(value.clone());
        let result = evaluate_match_condition(&cond, &json_value);
        prop_assert_eq!(result, value.starts_with(&prefix));
    }

    // ends_with consistency
    #[test]
    fn ends_with_matches_std(
        value in "[a-zA-Z0-9]{0,20}",
        suffix in "[a-zA-Z0-9]{0,5}",
    ) {
        let cond = MatchCondition {
            ends_with: Some(suffix.clone()),
            ..empty_match_condition()
        };
        let json_value = Value::String(value.clone());
        let result = evaluate_match_condition(&cond, &json_value);
        prop_assert_eq!(result, value.ends_with(&suffix));
    }

    // gt/lte are strict complements for all finite f64 values
    #[test]
    fn gt_lte_complementary(a in -1000.0f64..1000.0, b in -1000.0f64..1000.0) {
        let gt_cond = MatchCondition {
            gt: Some(b),
            ..empty_match_condition()
        };
        let lte_cond = MatchCondition {
            lte: Some(b),
            ..empty_match_condition()
        };
        let value = json!(a);
        let gt_result = evaluate_match_condition(&gt_cond, &value);
        let lte_result = evaluate_match_condition(&lte_cond, &value);
        prop_assert_ne!(gt_result, lte_result,
            "gt({}, {})={} and lte({}, {})={} must be strict complements",
            a, b, gt_result, a, b, lte_result);
    }

    // lt/gte are strict complements for all finite f64 values
    #[test]
    fn lt_gte_complementary(a in -1000.0f64..1000.0, b in -1000.0f64..1000.0) {
        let lt_cond = MatchCondition {
            lt: Some(b),
            ..empty_match_condition()
        };
        let gte_cond = MatchCondition {
            gte: Some(b),
            ..empty_match_condition()
        };
        let value = json!(a);
        let lt_result = evaluate_match_condition(&lt_cond, &value);
        let gte_result = evaluate_match_condition(&gte_cond, &value);
        prop_assert_ne!(lt_result, gte_result,
            "lt({}, {})={} and gte({}, {})={} must be strict complements",
            a, b, lt_result, a, b, gte_result);
    }

    // any_of([x], value) == equality(x, value)
    #[test]
    fn any_of_single_equals_equality(n in -100i64..100) {
        let value = json!(n);
        let target = json!(n);
        let any_of_cond = Condition::Operators(MatchCondition {
            any_of: Some(vec![target.clone()]),
            ..empty_match_condition()
        });
        let eq_cond = Condition::Equality(target);
        prop_assert_eq!(
            evaluate_condition(&any_of_cond, &value),
            evaluate_condition(&eq_cond, &value),
        );
    }

    // Numeric equality is reflexive
    #[test]
    fn numeric_equality_reflexive(n in -1000i64..1000) {
        let int_val = json!(n);
        let float_val = json!(n as f64);
        let cond = Condition::Equality(json!(n));
        prop_assert!(evaluate_condition(&cond, &int_val), "int {} should equal itself", n);
        prop_assert!(evaluate_condition(&cond, &float_val), "float {} should equal int {}", n as f64, n);
    }

    // Type mismatches return false, never panic
    #[test]
    fn type_mismatch_returns_false(n in -100i64..100) {
        let num_value = json!(n);
        // String operation on number should return false
        let cond = MatchCondition {
            contains: Some("foo".to_string()),
            ..empty_match_condition()
        };
        prop_assert!(!evaluate_match_condition(&cond, &num_value));

        // Numeric operation on string should return false
        let str_value = json!("hello");
        let num_cond = MatchCondition {
            gt: Some(0.0),
            ..empty_match_condition()
        };
        prop_assert!(!evaluate_match_condition(&num_cond, &str_value));
    }
}
