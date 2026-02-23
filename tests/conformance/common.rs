/// Structural equality: ignore field ordering, compare values deeply.
/// Treat missing optional fields as equivalent to null.
pub fn values_structurally_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => {
            // Compare numerically
            if let (Some(a), Some(b)) = (a.as_f64(), b.as_f64()) {
                (a - b).abs() < f64::EPSILON
            } else {
                a == b
            }
        }
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(a, b)| values_structurally_equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            // Check all keys in expected are present and equal in actual
            // Skip keys in actual that are null and not in expected (optional fields)
            for (key, val_b) in b {
                match a.get(key) {
                    Some(val_a) => {
                        if !values_structurally_equal(val_a, val_b) {
                            return false;
                        }
                    }
                    None => {
                        if !val_b.is_null() {
                            return false;
                        }
                    }
                }
            }
            // Check for keys in actual that are not in expected and not null
            for (key, val_a) in a {
                if !b.contains_key(key) && !val_a.is_null() {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}
