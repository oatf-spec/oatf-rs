use oatf::primitives::parse_duration;
use proptest::prelude::*;
use std::time::Duration;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn valid_shorthand_seconds(n in 1u64..=999999) {
        let input = format!("{}s", n);
        let result = parse_duration(&input);
        prop_assert!(result.is_ok(), "parse_duration({:?}) failed: {:?}", input, result);
        prop_assert_eq!(result.unwrap(), Duration::from_secs(n));
    }

    #[test]
    fn valid_shorthand_minutes(n in 1u64..=999999) {
        let input = format!("{}m", n);
        let result = parse_duration(&input);
        prop_assert!(result.is_ok(), "parse_duration({:?}) failed: {:?}", input, result);
        prop_assert_eq!(result.unwrap(), Duration::from_secs(n * 60));
    }

    #[test]
    fn valid_shorthand_hours(n in 1u64..=999999) {
        let input = format!("{}h", n);
        let result = parse_duration(&input);
        prop_assert!(result.is_ok(), "parse_duration({:?}) failed: {:?}", input, result);
        prop_assert_eq!(result.unwrap(), Duration::from_secs(n * 3600));
    }

    #[test]
    fn valid_shorthand_days(n in 1u64..=999999) {
        let input = format!("{}d", n);
        let result = parse_duration(&input);
        prop_assert!(result.is_ok(), "parse_duration({:?}) failed: {:?}", input, result);
        prop_assert_eq!(result.unwrap(), Duration::from_secs(n * 86400));
    }

    #[test]
    fn iso_seconds_equals_shorthand(n in 1u64..=999999) {
        let iso = format!("PT{}S", n);
        let shorthand = format!("{}s", n);
        let iso_result = parse_duration(&iso).unwrap();
        let short_result = parse_duration(&shorthand).unwrap();
        prop_assert_eq!(iso_result, short_result,
            "PT{}S ({:?}) != {}s ({:?})", n, iso_result, n, short_result);
    }

    #[test]
    fn iso_minutes_equals_shorthand(n in 1u64..=999999) {
        let iso = format!("PT{}M", n);
        let shorthand = format!("{}m", n);
        let iso_result = parse_duration(&iso).unwrap();
        let short_result = parse_duration(&shorthand).unwrap();
        prop_assert_eq!(iso_result, short_result);
    }

    #[test]
    fn iso_hours_equals_shorthand(n in 1u64..=999999) {
        let iso = format!("PT{}H", n);
        let shorthand = format!("{}h", n);
        let iso_result = parse_duration(&iso).unwrap();
        let short_result = parse_duration(&shorthand).unwrap();
        prop_assert_eq!(iso_result, short_result);
    }

    #[test]
    fn iso_days_equals_shorthand(n in 1u64..=999999) {
        let iso = format!("P{}D", n);
        let shorthand = format!("{}d", n);
        let iso_result = parse_duration(&iso).unwrap();
        let short_result = parse_duration(&shorthand).unwrap();
        prop_assert_eq!(iso_result, short_result);
    }

    #[test]
    fn arbitrary_string_never_panics(s in "\\PC{0,30}") {
        let _ = parse_duration(&s);
    }

    #[test]
    fn valid_iso_combined(
        days in 0u64..=30,
        hours in 0u64..=23,
        minutes in 0u64..=59,
        seconds in 0u64..=59,
    ) {
        // At least one component must be nonzero
        prop_assume!(days > 0 || hours > 0 || minutes > 0 || seconds > 0);

        let mut input = String::from("P");
        if days > 0 {
            input.push_str(&format!("{}D", days));
        }
        if hours > 0 || minutes > 0 || seconds > 0 {
            input.push('T');
            if hours > 0 { input.push_str(&format!("{}H", hours)); }
            if minutes > 0 { input.push_str(&format!("{}M", minutes)); }
            if seconds > 0 { input.push_str(&format!("{}S", seconds)); }
        }

        let result = parse_duration(&input);
        prop_assert!(result.is_ok(), "parse_duration({:?}) failed: {:?}", input, result);

        let expected_secs = days * 86400 + hours * 3600 + minutes * 60 + seconds;
        prop_assert_eq!(result.unwrap(), Duration::from_secs(expected_secs));
    }
}
