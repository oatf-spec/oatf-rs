#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use oatf::primitives::evaluate_condition;
use oatf::types::{Condition, MatchCondition};
use serde_json::Value;

/// Generate an arbitrary MatchCondition from fuzzer bytes.
fn arbitrary_match_condition(u: &mut Unstructured<'_>) -> arbitrary::Result<MatchCondition> {
    Ok(MatchCondition {
        contains: Option::<String>::arbitrary(u)?,
        starts_with: Option::<String>::arbitrary(u)?,
        ends_with: Option::<String>::arbitrary(u)?,
        regex: Option::<String>::arbitrary(u)?,
        any_of: {
            if bool::arbitrary(u)? {
                let len = u.int_in_range(0..=5)?;
                let mut v = Vec::with_capacity(len);
                for _ in 0..len {
                    v.push(arbitrary_value(u)?);
                }
                Some(v)
            } else {
                None
            }
        },
        gt: Option::<f64>::arbitrary(u)?,
        lt: Option::<f64>::arbitrary(u)?,
        gte: Option::<f64>::arbitrary(u)?,
        lte: Option::<f64>::arbitrary(u)?,
        exists: Option::<bool>::arbitrary(u)?,
    })
}

/// Generate a simple arbitrary JSON value from fuzzer bytes.
fn arbitrary_value(u: &mut Unstructured<'_>) -> arbitrary::Result<Value> {
    match u.int_in_range(0..=4)? {
        0 => Ok(Value::Null),
        1 => Ok(Value::Bool(bool::arbitrary(u)?)),
        2 => {
            let n = f64::arbitrary(u)?;
            Ok(serde_json::Number::from_f64(n)
                .map(Value::Number)
                .unwrap_or(Value::Null))
        }
        3 => Ok(Value::String(String::arbitrary(u)?)),
        _ => Ok(Value::Null),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let cond = match arbitrary_match_condition(&mut u) {
        Ok(c) => c,
        Err(_) => return,
    };

    let value = match arbitrary_value(&mut u) {
        Ok(v) => v,
        Err(_) => return,
    };

    let _ = evaluate_condition(&Condition::Operators(cond), &value);
});
