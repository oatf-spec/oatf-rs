//! Execution primitives per SDK spec §5.1–§5.11.
//!
//! Shared utility operations used by both entry points and evaluation.

use crate::enums::AdvanceReason;
use crate::error::{Diagnostic, DiagnosticSeverity, ParseError, ParseErrorKind};
use crate::types::*;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

// Re-export extract_protocol from event_registry (§5.10)
pub use crate::event_registry::extract_protocol;
// Re-export resolve_event_qualifier from event_registry (§7)
pub use crate::event_registry::resolve_event_qualifier;

// ─── §5.1.1 resolve_simple_path ─────────────────────────────────────────────

/// Resolves a simple dot-path against a value tree.
///
/// Returns the single value at the path, or `None` if any segment fails to
/// resolve. Empty path returns the root value.
pub fn resolve_simple_path(path: &str, value: &Value) -> Option<Value> {
    if path.is_empty() {
        return Some(value.clone());
    }

    let mut current = value;
    for segment in path.split('.') {
        match current.as_object() {
            Some(obj) => match obj.get(segment) {
                Some(v) => current = v,
                None => return None,
            },
            None => return None,
        }
    }
    Some(current.clone())
}

// ─── §5.1.2 resolve_wildcard_path ───────────────────────────────────────────

/// Resolves a wildcard dot-path against a value tree.
///
/// Returns all values that match, potentially expanding across array elements
/// via `[*]` wildcards. Returns an empty vec if the path does not match.
/// Empty path returns the root value as a single-element list.
pub fn resolve_wildcard_path(path: &str, value: &Value) -> Vec<Value> {
    if path.is_empty() {
        return vec![value.clone()];
    }

    let segments = match split_wildcard_segments(path) {
        Some(s) => s,
        None => return vec![],
    };

    let mut current = vec![value.clone()];

    for seg in &segments {
        if current.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for val in &current {
            if seg.wildcard {
                // First access the field name, then fan out
                let target = if seg.name.is_empty() {
                    val.clone()
                } else {
                    match val.as_object().and_then(|o| o.get(&seg.name)) {
                        Some(v) => v.clone(),
                        None => continue,
                    }
                };
                if let Some(arr) = target.as_array() {
                    next.extend(arr.iter().cloned());
                }
            } else if let Some(v) = val.as_object().and_then(|o| o.get(&seg.name)) {
                next.push(v.clone());
            }
        }
        current = next;
    }

    current
}

struct WildcardSegment {
    name: String,
    wildcard: bool,
}

fn split_wildcard_segments(path: &str) -> Option<Vec<WildcardSegment>> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = path.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '.' => {
                if current.is_empty() && segments.is_empty() {
                    return None; // leading dot
                }
                if !current.is_empty() {
                    segments.push(WildcardSegment {
                        name: current.clone(),
                        wildcard: false,
                    });
                    current.clear();
                }
                i += 1;
            }
            '[' => {
                // Must be [*]
                if i + 2 < chars.len() && chars[i + 1] == '*' && chars[i + 2] == ']' {
                    segments.push(WildcardSegment {
                        name: current.clone(),
                        wildcard: true,
                    });
                    current.clear();
                    i += 3;
                    // After [*], must be . or end
                    if i < chars.len() {
                        if chars[i] == '.' {
                            i += 1;
                        } else {
                            return None;
                        }
                    }
                } else {
                    return None;
                }
            }
            c => {
                current.push(c);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        segments.push(WildcardSegment {
            name: current,
            wildcard: false,
        });
    }

    Some(segments)
}

// ─── §5.2 parse_duration ────────────────────────────────────────────────────

/// Parses a duration string in either shorthand or ISO 8601 format.
///
/// Accepted: `30s`, `5m`, `1h`, `2d`, `PT30S`, `PT5M`, `PT1H`, `P2D`,
/// `P1DT12H30M15S`, etc.
pub fn parse_duration(input: &str) -> Result<Duration, ParseError> {
    if input.is_empty() {
        return Err(duration_error("empty duration string"));
    }

    if input.starts_with('P') {
        parse_iso_duration(input)
    } else {
        parse_shorthand_duration(input)
    }
}

fn parse_shorthand_duration(input: &str) -> Result<Duration, ParseError> {
    if input.len() < 2 {
        return Err(duration_error(&format!(
            "invalid shorthand duration: '{}'",
            input
        )));
    }

    // Split before the last character safely (handles multi-byte chars)
    let split_pos = input
        .char_indices()
        .next_back()
        .map(|(i, _)| i)
        .unwrap_or(0);
    let (num_str, unit) = input.split_at(split_pos);
    let n: u64 = num_str
        .parse()
        .map_err(|_| duration_error(&format!("invalid shorthand duration: '{}'", input)))?;

    let secs = match unit {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        "d" => n.checked_mul(86400),
        _ => {
            return Err(duration_error(&format!(
                "unknown duration unit: '{}'",
                unit
            )));
        }
    };

    let secs =
        secs.ok_or_else(|| duration_error(&format!("duration value too large: '{}'", input)))?;

    Ok(Duration::from_secs(secs))
}

fn parse_iso_duration(input: &str) -> Result<Duration, ParseError> {
    let rest = &input[1..]; // strip leading 'P'
    let mut total_secs: u64 = 0;

    let (date_part, time_part) = if let Some(t_pos) = rest.find('T') {
        (&rest[..t_pos], Some(&rest[t_pos + 1..]))
    } else {
        (rest, None)
    };

    // Parse date component (only D supported)
    if !date_part.is_empty() {
        if let Some(num_str) = date_part.strip_suffix('D') {
            let n: u64 = num_str
                .parse()
                .map_err(|_| duration_error(&format!("invalid ISO duration: '{}'", input)))?;
            total_secs = n
                .checked_mul(86400)
                .and_then(|v| total_secs.checked_add(v))
                .ok_or_else(|| duration_error(&format!("duration value too large: '{}'", input)))?;
        } else {
            return Err(duration_error(&format!(
                "invalid ISO duration: '{}'",
                input
            )));
        }
    }

    // Parse time components (H, M, S)
    if let Some(time) = time_part {
        if time.is_empty() {
            return Err(duration_error(&format!(
                "invalid ISO duration: '{}'",
                input
            )));
        }
        let mut remaining = time;
        // Hours
        if let Some(h_pos) = remaining.find('H') {
            let n: u64 = remaining[..h_pos]
                .parse()
                .map_err(|_| duration_error(&format!("invalid ISO duration: '{}'", input)))?;
            total_secs = n
                .checked_mul(3600)
                .and_then(|v| total_secs.checked_add(v))
                .ok_or_else(|| duration_error(&format!("duration value too large: '{}'", input)))?;
            remaining = &remaining[h_pos + 1..];
        }
        // Minutes
        if let Some(m_pos) = remaining.find('M') {
            let n: u64 = remaining[..m_pos]
                .parse()
                .map_err(|_| duration_error(&format!("invalid ISO duration: '{}'", input)))?;
            total_secs = n
                .checked_mul(60)
                .and_then(|v| total_secs.checked_add(v))
                .ok_or_else(|| duration_error(&format!("duration value too large: '{}'", input)))?;
            remaining = &remaining[m_pos + 1..];
        }
        // Seconds
        if let Some(s_pos) = remaining.find('S') {
            let n: u64 = remaining[..s_pos]
                .parse()
                .map_err(|_| duration_error(&format!("invalid ISO duration: '{}'", input)))?;
            total_secs = total_secs
                .checked_add(n)
                .ok_or_else(|| duration_error(&format!("duration value too large: '{}'", input)))?;
            remaining = &remaining[s_pos + 1..];
        }
        if !remaining.is_empty() {
            return Err(duration_error(&format!(
                "invalid ISO duration: '{}'",
                input
            )));
        }
    }

    // Must have at least some duration component
    if date_part.is_empty() && time_part.is_none() {
        return Err(duration_error(&format!(
            "invalid ISO duration: '{}'",
            input
        )));
    }

    Ok(Duration::from_secs(total_secs))
}

fn duration_error(message: &str) -> ParseError {
    ParseError {
        kind: ParseErrorKind::Syntax,
        message: message.to_string(),
        path: None,
        line: None,
        column: None,
    }
}

// ─── §5.3 evaluate_condition ────────────────────────────────────────────────

/// Evaluates a condition against a resolved value.
///
/// If `condition` is a bare value, performs deep equality comparison.
/// If `condition` is a `MatchCondition` object, evaluates each present operator
/// — all must match (AND logic).
pub fn evaluate_condition(condition: &Condition, value: &Value) -> bool {
    match condition {
        Condition::Equality(expected) => values_deep_equal(value, expected),
        Condition::Operators(cond) => evaluate_match_condition(cond, value),
    }
}

/// Evaluate a MatchCondition (set of operators) against a value with AND logic.
pub fn evaluate_match_condition(cond: &MatchCondition, value: &Value) -> bool {
    // Each present operator must pass (AND logic)
    if let Some(ref s) = cond.contains {
        match value.as_str() {
            Some(v) => {
                if !v.contains(s.as_str()) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref s) = cond.starts_with {
        match value.as_str() {
            Some(v) => {
                if !v.starts_with(s.as_str()) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref s) = cond.ends_with {
        match value.as_str() {
            Some(v) => {
                if !v.ends_with(s.as_str()) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref pattern) = cond.regex {
        match value.as_str() {
            Some(v) => {
                if let Ok(re) = Regex::new(pattern) {
                    if !re.is_match(v) {
                        return false;
                    }
                } else {
                    return false; // invalid regex → false
                }
            }
            None => return false,
        }
    }

    if let Some(ref items) = cond.any_of
        && !items.iter().any(|item| values_deep_equal(value, item))
    {
        return false;
    }

    if let Some(threshold) = cond.gt {
        match value.as_f64() {
            Some(v) if v > threshold => {}
            _ => return false,
        }
    }

    if let Some(threshold) = cond.lt {
        match value.as_f64() {
            Some(v) if v < threshold => {}
            _ => return false,
        }
    }

    if let Some(threshold) = cond.gte {
        match value.as_f64() {
            Some(v) if v >= threshold => {}
            _ => return false,
        }
    }

    if let Some(threshold) = cond.lte {
        match value.as_f64() {
            Some(v) if v <= threshold => {}
            _ => return false,
        }
    }

    // exists is handled by evaluate_predicate, not here
    true
}

/// Deep equality comparison per SDK spec §5.3.
///
/// Integer 42 equals float 42.0; object key order is irrelevant;
/// arrays compare element-wise by position and length.
fn values_deep_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => match (a.as_f64(), b.as_f64()) {
            (Some(fa), Some(fb)) => fa == fb,
            _ => a == b,
        },
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| values_deep_equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            if a.len() != b.len() {
                return false;
            }
            a.iter()
                .all(|(k, v)| b.get(k).is_some_and(|bv| values_deep_equal(v, bv)))
        }
        _ => false,
    }
}

// ─── §5.4 evaluate_predicate ────────────────────────────────────────────────

/// Evaluates a match predicate against a value. All entries combined with AND.
///
/// For each `(path, condition)` entry:
/// - Resolve the path via `resolve_simple_path`
/// - Handle `exists` operator at the path-resolution level
/// - Evaluate remaining condition operators against resolved value
///
/// Empty predicate → true.
pub fn evaluate_predicate(predicate: &MatchPredicate, value: &Value) -> bool {
    for (path, entry) in predicate {
        let resolved = resolve_simple_path(path, value);

        match entry {
            MatchEntry::Scalar(expected) => match &resolved {
                Some(val) => {
                    if !values_deep_equal(val, expected) {
                        return false;
                    }
                }
                None => return false,
            },
            MatchEntry::Condition(cond) => {
                match cond {
                    MatchCondition {
                        exists: Some(false),
                        ..
                    } => {
                        // exists: false — path should NOT resolve
                        if resolved.is_some() {
                            return false;
                        }
                        // §5.4: exists: false with no other operators → true;
                        // exists: false with other operators → false
                        let has_other_ops = cond.contains.is_some()
                            || cond.starts_with.is_some()
                            || cond.ends_with.is_some()
                            || cond.regex.is_some()
                            || cond.any_of.is_some()
                            || cond.gt.is_some()
                            || cond.lt.is_some()
                            || cond.gte.is_some()
                            || cond.lte.is_some();
                        if has_other_ops {
                            return false;
                        }
                    }
                    MatchCondition {
                        exists: Some(true), ..
                    } => {
                        // exists: true — path MUST resolve
                        if resolved.is_none() {
                            return false;
                        }
                        // Evaluate remaining operators
                        let val = resolved.as_ref().unwrap();
                        if !evaluate_match_condition_excluding_exists(cond, val) {
                            return false;
                        }
                    }
                    _ => {
                        // No exists operator
                        match &resolved {
                            Some(val) => {
                                if !evaluate_match_condition(cond, val) {
                                    return false;
                                }
                            }
                            None => return false,
                        }
                    }
                }
            }
        }
    }
    true
}

/// Evaluate all operators in a MatchCondition except `exists`.
fn evaluate_match_condition_excluding_exists(cond: &MatchCondition, value: &Value) -> bool {
    // Build a temporary MatchCondition without exists
    let without_exists = MatchCondition {
        contains: cond.contains.clone(),
        starts_with: cond.starts_with.clone(),
        ends_with: cond.ends_with.clone(),
        regex: cond.regex.clone(),
        any_of: cond.any_of.clone(),
        gt: cond.gt,
        lt: cond.lt,
        gte: cond.gte,
        lte: cond.lte,
        exists: None,
    };
    evaluate_match_condition(&without_exists, value)
}

// ─── §5.5 interpolate_template ──────────────────────────────────────────────

/// Resolves template expressions in a string.
///
/// Returns the interpolated string and any diagnostics (W-004 warnings for
/// undefined references).
pub fn interpolate_template(
    template: &str,
    extractors: &HashMap<String, String>,
    request: Option<&Value>,
    response: Option<&Value>,
) -> (String, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();

    // Step 1: Replace \{{ with placeholder
    const PLACEHOLDER: &str = "\x00ESCAPED_OPEN_BRACE\x00";
    let working = template.replace("\\{{", PLACEHOLDER);

    // Step 2-3: Find and replace all {{...}} expressions
    let mut result = String::new();
    let mut remaining = working.as_str();

    while let Some(start) = remaining.find("{{") {
        result.push_str(&remaining[..start]);

        let after_open = &remaining[start + 2..];
        if let Some(end) = after_open.find("}}") {
            let expr = &after_open[..end];

            // Resolution order:
            // a. Check extractors map
            if let Some(val) = extractors.get(expr) {
                result.push_str(val);
            }
            // b. If starts with "request." and request is Some
            else if let Some(rest) = expr.strip_prefix("request.") {
                if let Some(req) = request {
                    match resolve_simple_path(rest, req) {
                        Some(v) => result.push_str(&value_to_string(&v)),
                        None => {
                            diagnostics.push(w004_diagnostic(expr));
                        }
                    }
                } else {
                    diagnostics.push(w004_diagnostic(expr));
                }
            }
            // c. If starts with "response." and response is Some
            else if let Some(rest) = expr.strip_prefix("response.") {
                if let Some(resp) = response {
                    match resolve_simple_path(rest, resp) {
                        Some(v) => result.push_str(&value_to_string(&v)),
                        None => {
                            diagnostics.push(w004_diagnostic(expr));
                        }
                    }
                } else {
                    diagnostics.push(w004_diagnostic(expr));
                }
            }
            // d. Otherwise, empty string + W-004
            else {
                diagnostics.push(w004_diagnostic(expr));
            }

            remaining = &after_open[end + 2..];
        } else {
            // Unclosed {{ — just pass through
            result.push_str("{{");
            remaining = after_open;
        }
    }
    result.push_str(remaining);

    // Step 4: Restore placeholders to literal {{
    let final_result = result.replace(PLACEHOLDER, "{{");

    (final_result, diagnostics)
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        // Objects and arrays serialize to compact JSON
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

fn w004_diagnostic(expr: &str) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Warning,
        code: "W-004".to_string(),
        path: None,
        message: format!("unresolvable template reference: '{}'", expr),
    }
}

// ─── §5.5a interpolate_value ─────────────────────────────────────────────────

/// Recursively walks a JSON value tree and interpolates template expressions
/// in all string leaves that contain `{{`.
///
/// Returns a new `Value` with all templates resolved and aggregated diagnostics.
pub fn interpolate_value(
    value: &Value,
    extractors: &HashMap<String, String>,
    request: Option<&Value>,
    response: Option<&Value>,
) -> (Value, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let result = interpolate_value_inner(value, extractors, request, response, &mut diagnostics);
    (result, diagnostics)
}

fn interpolate_value_inner(
    value: &Value,
    extractors: &HashMap<String, String>,
    request: Option<&Value>,
    response: Option<&Value>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Value {
    match value {
        Value::String(s) => {
            if s.contains("{{") {
                let (interpolated, diags) =
                    interpolate_template(s, extractors, request, response);
                diagnostics.extend(diags);
                Value::String(interpolated)
            } else {
                value.clone()
            }
        }
        Value::Object(map) => {
            let new_map: serde_json::Map<String, Value> = map
                .iter()
                .map(|(k, v)| {
                    let new_v =
                        interpolate_value_inner(v, extractors, request, response, diagnostics);
                    (k.clone(), new_v)
                })
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => {
            let new_arr: Vec<Value> = arr
                .iter()
                .map(|v| interpolate_value_inner(v, extractors, request, response, diagnostics))
                .collect();
            Value::Array(new_arr)
        }
        // Null, Bool, Number — pass through unchanged
        _ => value.clone(),
    }
}

// ─── §5.6 evaluate_extractor ────────────────────────────────────────────────

/// Applies an extractor to a message, capturing a value.
///
/// - `json_path`: Evaluate JSONPath; return first match serialized to compact JSON.
/// - `regex`: Evaluate regex; return first capture group value.
///
/// The `direction` parameter indicates whether the message is a request or
/// response. If it does not match the extractor's `source` field, `None` is
/// returned immediately (the extractor does not apply to this direction).
///
/// Returns `None` for no match. `Some("")` is a valid result.
pub fn evaluate_extractor(
    extractor: &Extractor,
    message: &Value,
    direction: crate::enums::ExtractorSource,
) -> Option<String> {
    if extractor.source != direction {
        return None;
    }
    match extractor.extractor_type {
        crate::enums::ExtractorType::JsonPath => {
            evaluate_extractor_jsonpath(&extractor.selector, message)
        }
        crate::enums::ExtractorType::Regex => {
            evaluate_extractor_regex(&extractor.selector, message)
        }
    }
}

fn evaluate_extractor_jsonpath(selector: &str, message: &Value) -> Option<String> {
    let path = serde_json_path::JsonPath::parse(selector).ok()?;
    let node_list = path.query(message);
    let first = node_list.first()?;

    // Serialize: scalars to their natural representation, non-scalars to compact JSON
    match first {
        Value::String(s) => Some(s.clone()),
        Value::Null => Some("null".to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => Some(serde_json::to_string(first).unwrap_or_default()),
    }
}

fn evaluate_extractor_regex(selector: &str, message: &Value) -> Option<String> {
    let text = match message {
        Value::String(s) => s.clone(),
        _ => serde_json::to_string(message).unwrap_or_default(),
    };

    let re = Regex::new(selector).ok()?;
    let caps = re.captures(&text)?;

    // Must have at least one capture group; return first group
    if caps.len() < 2 {
        return None; // no capture groups
    }
    caps.get(1).map(|m| m.as_str().to_string())
}

// ─── §5.7 select_response ───────────────────────────────────────────────────

/// Selects the first matching response entry from an ordered list.
///
/// First-match-wins for entries with `when` predicates. Falls back to
/// the default entry (no `when`) if no predicate-bearing entry matches.
pub fn select_response<'a>(
    entries: &'a [ResponseEntry],
    request: &Value,
) -> Option<&'a ResponseEntry> {
    let mut default_entry: Option<&ResponseEntry> = None;

    for entry in entries {
        match &entry.when {
            Some(predicate) => {
                if evaluate_predicate(predicate, request) {
                    return Some(entry);
                }
            }
            None => {
                if default_entry.is_none() {
                    default_entry = Some(entry);
                }
            }
        }
    }

    default_entry
}

// ─── §5.8 evaluate_trigger ──────────────────────────────────────────────────

/// Evaluates whether a trigger condition is satisfied for phase advancement.
///
/// `protocol` identifies the wire protocol (e.g. `"mcp"`, `"a2a"`, `"ag_ui"`)
/// and is used to key the qualifier resolution registry.
///
/// `state` is a mutable reference to per-trigger state that persists across
/// calls. The SDK increments `state.event_count` only when the incoming event
/// fully matches (base type + qualifier + predicate).
pub fn evaluate_trigger(
    trigger: &Trigger,
    event: Option<&ProtocolEvent>,
    elapsed: Duration,
    state: &mut TriggerState,
    protocol: &str,
) -> TriggerResult {
    // 1. Check timeout
    if let Some(after) = &trigger.after
        && let Ok(timeout) = parse_duration(after)
        && elapsed >= timeout
    {
        return TriggerResult::Advanced {
            reason: AdvanceReason::Timeout,
        };
    }

    // 2. Check event match
    if let (Some(trigger_event), Some(ev)) = (&trigger.event, event) {
        let (trigger_base, trigger_qualifier) = parse_event_qualifier(trigger_event);
        let (event_base, _) = parse_event_qualifier(&ev.event_type);

        if trigger_base != event_base {
            return TriggerResult::NotAdvanced;
        }

        // 3. Qualifier comparison (if trigger specifies one)
        if let Some(tq) = trigger_qualifier {
            // §5.8 step 2c-i: event.qualifier first, then content-based resolution
            let resolved = ev
                .qualifier
                .clone()
                .or_else(|| {
                    crate::event_registry::resolve_event_qualifier(
                        protocol,
                        event_base,
                        &ev.content,
                    )
                });
            match resolved {
                Some(ref eq) if eq == tq => {} // match
                _ => return TriggerResult::NotAdvanced,
            }
        }

        // 4. Check match predicate if present
        if let Some(predicate) = &trigger.match_predicate
            && !evaluate_predicate(predicate, &ev.content)
        {
            return TriggerResult::NotAdvanced;
        }

        // 5. Full match — increment count, then check threshold
        state.event_count += 1;
        let required_count = trigger.count.unwrap_or(1) as u64;
        if state.event_count >= required_count {
            return TriggerResult::Advanced {
                reason: AdvanceReason::EventMatched,
            };
        }
    }

    TriggerResult::NotAdvanced
}

// ─── §5.9 parse_event_qualifier ─────────────────────────────────────────────

/// Splits an event type string on the first `:` separator.
///
/// Returns `(base_event, optional_qualifier)`.
pub fn parse_event_qualifier(event_string: &str) -> (&str, Option<&str>) {
    match event_string.find(':') {
        Some(pos) => (&event_string[..pos], Some(&event_string[pos + 1..])),
        None => (event_string, None),
    }
}

// ─── §5.11 compute_effective_state ──────────────────────────────────────────

/// Computes the effective state at a given phase by applying state inheritance.
///
/// Walk phases 0..=phase_index: if a phase defines `state`, that becomes
/// the current; if it omits `state`, the previous carries forward.
pub fn compute_effective_state(phases: &[Phase], phase_index: usize) -> Value {
    let mut effective = Value::Null;

    for (i, phase) in phases.iter().enumerate() {
        if i > phase_index {
            break;
        }
        if let Some(state) = &phase.state {
            effective = state.clone();
        }
    }

    effective
}
