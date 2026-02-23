//! Document validation against conformance rules V-001 through V-045.
//!
//! Returns **all** errors and warnings, not just the first. Validation does not
//! modify the document.

use crate::error::*;
use crate::event_registry::{extract_protocol, is_event_valid_for_mode, strip_event_qualifier};
use crate::surface::{KNOWN_MODES, KNOWN_PROTOCOLS, lookup_surface};
use crate::types::*;
use regex::Regex;
use std::sync::LazyLock;

// ─── Cached regexes ─────────────────────────────────────────────────────────

static MODE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]*_(server|client)$").unwrap());

static SNAKE_CASE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]*$").unwrap());

static ATTACK_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9-]*-[0-9]{3,}$").unwrap());

static INDICATOR_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9-]*-[0-9]{3,}-[0-9]{2,}$").unwrap());

static CROSS_ACTOR_REF_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\.([a-zA-Z_][a-zA-Z0-9_]*)\}\}").unwrap()
});

static CEL_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[_a-zA-Z][_a-zA-Z0-9]*$").unwrap());

static SHORTHAND_DURATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]+[smhd]$").unwrap());

static ISO_DURATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^P([0-9]+D)?(T([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$").unwrap());

static PROTOCOL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]*$").unwrap());

/// Validate a parsed document against all 45 conformance rules (V-001..V-045).
/// Returns a ValidationResult containing all errors and warnings found.
pub fn validate(doc: &Document) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    w001_oatf_key_ordering(doc, &mut warnings);
    v001_oatf_version(doc, &mut errors);
    // V-003 (attack present) and V-004 (required fields) are enforced by
    // serde deserialization during parse — no runtime check needed here.
    v005_enum_values(doc, &mut errors);
    v006_indicators_non_empty(doc, &mut errors);
    v007_phases_non_empty(doc, &mut errors);
    v008_terminal_phase(doc, &mut errors);
    v009_first_phase_state(doc, &mut errors);
    v010_unique_indicator_ids(doc, &mut errors);
    v011_unique_phase_names(doc, &mut errors);
    v012_exactly_one_detection_key(doc, &mut errors);
    v012_pattern_form_ambiguity(doc, &mut errors);
    v013_regex_valid(doc, &mut errors);
    v014_cel_valid(doc, &mut errors);
    v015_jsonpath_valid(doc, &mut errors);
    v016_template_syntax(doc, &mut errors);
    v017_severity_confidence(doc, &mut errors);
    v018_surface_protocol(doc, &mut errors, &mut warnings);
    v019_count_match_require_event(doc, &mut errors);
    v021_target_path_syntax(doc, &mut errors);
    v022_semantic_threshold(doc, &mut errors);
    v023_attack_id_format(doc, &mut errors);
    v024_indicator_id_format(doc, &mut errors);
    v025_indicator_confidence(doc, &mut errors);
    v026_expression_variables_paths(doc, &mut errors);
    v027_match_predicate_paths(doc, &mut errors);
    v028_conditional_requiredness(doc, &mut errors);
    v029_event_mode_validity(doc, &mut errors, &mut warnings);
    v030_mutual_exclusion(doc, &mut errors);
    v031_multi_actor_constraints(doc, &mut errors);
    v032_cross_actor_refs(doc, &mut errors);
    v033_content_synthesize_exclusivity(doc, &mut errors);
    v034_catch_all_constraints(doc, &mut errors);
    v035_synthesize_prompt(doc, &mut errors);
    v036_mode_protocol_pattern(doc, &mut errors, &mut warnings);
    v037_version_positive(doc, &mut errors);
    v038_trigger_after_duration(doc, &mut errors);
    v039_extractor_name_pattern(doc, &mut errors);
    v040_extractors_non_empty(doc, &mut errors);
    v041_expression_variable_keys(doc, &mut errors);
    v042_trigger_event_or_after(doc, &mut errors);
    v043_binding_specific_action_keys(doc, &mut errors);
    v044_regex_extractor_capture_group(doc, &mut errors);
    v045_on_enter_non_empty(doc, &mut errors);

    w004_undeclared_extractor_refs(doc, &mut warnings);
    w005_indicator_protocol_mismatch(doc, &mut warnings);

    ValidationResult { errors, warnings }
}

static TEMPLATE_VAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{([a-zA-Z_][a-zA-Z0-9_.]*)\}\}").unwrap());

// ─── Helper: collect all phases from all execution forms ─────────────────────

struct ActorInfo<'a> {
    #[allow(dead_code)]
    name: String,
    mode: Option<&'a str>,
    phases: &'a [Phase],
    path_prefix: String,
}

fn collect_actors(doc: &Document) -> Vec<ActorInfo<'_>> {
    let exec = &doc.attack.execution;
    if let Some(actors) = &exec.actors {
        actors
            .iter()
            .enumerate()
            .map(|(i, a)| ActorInfo {
                name: a.name.clone(),
                mode: Some(a.mode.as_str()),
                phases: &a.phases,
                path_prefix: format!("attack.execution.actors[{}]", i),
            })
            .collect()
    } else if let Some(phases) = &exec.phases {
        vec![ActorInfo {
            name: "default".to_string(),
            mode: exec.mode.as_deref(),
            phases: phases.as_slice(),
            path_prefix: "attack.execution".to_string(),
        }]
    } else if exec.state.is_some() {
        // Single-phase form: we represent as a virtual single phase
        vec![]
    } else {
        vec![]
    }
}

fn resolve_mode(
    doc: &Document,
    actor_mode: Option<&str>,
    phase_mode: Option<&str>,
) -> Option<String> {
    phase_mode
        .or(actor_mode)
        .or(doc.attack.execution.mode.as_deref())
        .map(|s| s.to_string())
}

// ─── V-001 ──────────────────────────────────────────────────────────────────

fn v001_oatf_version(doc: &Document, errors: &mut Vec<ValidationError>) {
    if doc.oatf != "0.1" {
        errors.push(ValidationError {
            rule: "V-001".to_string(),
            path: "oatf".to_string(),
            message: format!("oatf field must be '0.1', got '{}'", doc.oatf),
        });
    }
}

// ─── V-005 ──────────────────────────────────────────────────────────────────

fn v005_enum_values(doc: &Document, errors: &mut Vec<ValidationError>) {
    // V-005 validates execution.mode pattern; V-036 validates actor/phase modes.
    if let Some(mode) = &doc.attack.execution.mode
        && !MODE_RE.is_match(mode)
    {
        errors.push(ValidationError {
            rule: "V-005".to_string(),
            path: "attack.execution.mode".to_string(),
            message: format!(
                "mode must match [a-z][a-z0-9_]*_(server|client), got '{}'",
                mode
            ),
        });
    }

    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if lookup_surface(&ind.surface).is_none() {
                errors.push(ValidationError {
                    rule: "V-005".to_string(),
                    path: format!("attack.indicators[{}].surface", i),
                    message: format!("unknown surface: '{}'", ind.surface),
                });
            }
        }
    }
}

// ─── V-006 ──────────────────────────────────────────────────────────────────

fn v006_indicators_non_empty(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators
        && indicators.is_empty()
    {
        errors.push(ValidationError {
            rule: "V-006".to_string(),
            path: "attack.indicators".to_string(),
            message: "indicators, when present, must contain at least one entry".to_string(),
        });
    }
}

// ─── V-007 ──────────────────────────────────────────────────────────────────

fn v007_phases_non_empty(doc: &Document, errors: &mut Vec<ValidationError>) {
    let exec = &doc.attack.execution;
    if let Some(phases) = &exec.phases
        && phases.is_empty()
    {
        errors.push(ValidationError {
            rule: "V-007".to_string(),
            path: "attack.execution.phases".to_string(),
            message: "phases must contain at least one entry".to_string(),
        });
    }
    if let Some(actors) = &exec.actors {
        for (i, actor) in actors.iter().enumerate() {
            if actor.phases.is_empty() {
                errors.push(ValidationError {
                    rule: "V-007".to_string(),
                    path: format!("attack.execution.actors[{}].phases", i),
                    message: format!("actor '{}' must have at least one phase", actor.name),
                });
            }
        }
    }
}

// ─── V-008 ──────────────────────────────────────────────────────────────────

fn v008_terminal_phase(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        let mut terminal_count = 0;
        let mut last_terminal_idx = None;
        for (i, phase) in actor_info.phases.iter().enumerate() {
            if phase.trigger.is_none() {
                terminal_count += 1;
                last_terminal_idx = Some(i);
            }
        }
        if terminal_count > 1 {
            errors.push(ValidationError {
                rule: "V-008".to_string(),
                path: format!("{}.phases", actor_info.path_prefix),
                message: format!(
                    "at most one terminal phase (no trigger) per actor, found {}",
                    terminal_count
                ),
            });
        }
        if let Some(idx) = last_terminal_idx
            && idx != actor_info.phases.len() - 1
        {
            errors.push(ValidationError {
                rule: "V-008".to_string(),
                path: format!("{}.phases[{}]", actor_info.path_prefix, idx),
                message: "terminal phase must be the last phase in the actor's list".to_string(),
            });
        }
    }
}

// ─── V-009 ──────────────────────────────────────────────────────────────────

fn v009_first_phase_state(doc: &Document, errors: &mut Vec<ValidationError>) {
    let exec = &doc.attack.execution;
    // Single-phase form: execution.state must be present (handled by V-030)
    if let Some(phases) = &exec.phases
        && !phases.is_empty()
        && phases[0].state.is_none()
    {
        errors.push(ValidationError {
            rule: "V-009".to_string(),
            path: "attack.execution.phases[0]".to_string(),
            message: "first phase must include state".to_string(),
        });
    }
    if let Some(actors) = &exec.actors {
        for (i, actor) in actors.iter().enumerate() {
            if !actor.phases.is_empty() && actor.phases[0].state.is_none() {
                errors.push(ValidationError {
                    rule: "V-009".to_string(),
                    path: format!("attack.execution.actors[{}].phases[0]", i),
                    message: format!("first phase of actor '{}' must include state", actor.name),
                });
            }
        }
    }
}

// ─── V-010 ──────────────────────────────────────────────────────────────────

fn v010_unique_indicator_ids(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        let mut seen = std::collections::HashSet::new();
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(id) = &ind.id
                && !seen.insert(id.clone())
            {
                errors.push(ValidationError {
                    rule: "V-010".to_string(),
                    path: format!("attack.indicators[{}].id", i),
                    message: format!("duplicate indicator id: {}", id),
                });
            }
        }
    }
}

// ─── V-011 ──────────────────────────────────────────────────────────────────

fn v011_unique_phase_names(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        let mut seen = std::collections::HashSet::new();
        for (i, phase) in actor_info.phases.iter().enumerate() {
            if let Some(name) = &phase.name
                && !seen.insert(name.clone())
            {
                errors.push(ValidationError {
                    rule: "V-011".to_string(),
                    path: format!("{}.phases[{}].name", actor_info.path_prefix, i),
                    message: format!("duplicate phase name: {}", name),
                });
            }
        }
    }
}

// ─── V-012 ──────────────────────────────────────────────────────────────────

fn v012_exactly_one_detection_key(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            let count = [
                ind.pattern.is_some(),
                ind.expression.is_some(),
                ind.semantic.is_some(),
            ]
            .iter()
            .filter(|&&b| b)
            .count();
            if count != 1 {
                errors.push(ValidationError {
                    rule: "V-012".to_string(),
                    path: format!("attack.indicators[{}]", i),
                    message: format!(
                        "each indicator must have exactly one detection key (pattern, expression, or semantic), found {}",
                        count
                    ),
                });
            }
        }
    }
}

/// Reject patterns that have both `condition` and shorthand operator fields.
fn v012_pattern_form_ambiguity(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(pattern) = &ind.pattern
                && pattern.condition.is_some()
                && pattern.is_shorthand_fields_present()
            {
                errors.push(ValidationError {
                        rule: "V-012".to_string(),
                        path: format!("attack.indicators[{}].pattern", i),
                        message: "pattern must not have both 'condition' and shorthand operator fields (contains, regex, etc.)".to_string(),
                    });
            }
        }
    }
}

// ─── V-013 ──────────────────────────────────────────────────────────────────

fn v013_regex_valid(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(pattern) = &ind.pattern {
                // Check regex in shorthand form
                if let Some(re) = &pattern.regex
                    && let Err(e) = Regex::new(re)
                {
                    errors.push(ValidationError {
                        rule: "V-013".to_string(),
                        path: format!("attack.indicators[{}].pattern.regex", i),
                        message: format!("invalid regex: {}", e),
                    });
                }
                // Check regex in condition form
                if let Some(Condition::Operators(cond)) = &pattern.condition
                    && let Some(re) = &cond.regex
                    && let Err(e) = Regex::new(re)
                {
                    errors.push(ValidationError {
                        rule: "V-013".to_string(),
                        path: format!("attack.indicators[{}].pattern.condition.regex", i),
                        message: format!("invalid regex: {}", e),
                    });
                }
            }
        }
    }
    // Also check regex in match predicates (triggers and response entries)
    validate_regex_in_phases(doc, errors);
}

fn validate_regex_in_phases(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(trigger) = &phase.trigger
                && let Some(pred) = &trigger.match_predicate
            {
                for (key, entry) in pred {
                    if let MatchEntry::Condition(cond) = entry
                        && let Some(re) = &cond.regex
                        && let Err(e) = Regex::new(re)
                    {
                        errors.push(ValidationError {
                            rule: "V-013".to_string(),
                            path: format!(
                                "{}.phases[{}].trigger.match.{}.regex",
                                actor_info.path_prefix, pi, key
                            ),
                            message: format!("invalid regex: {}", e),
                        });
                    }
                }
            }
        }
    }
}

// ─── V-014 ──────────────────────────────────────────────────────────────────

fn v014_cel_valid(doc: &Document, errors: &mut Vec<ValidationError>) {
    #[cfg(feature = "cel-eval")]
    {
        if let Some(indicators) = &doc.attack.indicators {
            for (i, ind) in indicators.iter().enumerate() {
                if let Some(expr) = &ind.expression {
                    // Try to compile the CEL expression
                    if let Err(e) = cel::Program::compile(&expr.cel) {
                        errors.push(ValidationError {
                            rule: "V-014".to_string(),
                            path: format!("attack.indicators[{}].expression.cel", i),
                            message: format!("invalid CEL expression: {}", e),
                        });
                    }
                }
            }
        }
    }
}

// ─── V-015 ──────────────────────────────────────────────────────────────────

fn v015_jsonpath_valid(doc: &Document, errors: &mut Vec<ValidationError>) {
    // collect_actors() already handles actors, phases, and single-phase forms
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(extractors) = &phase.extractors {
                for (ei, ext) in extractors.iter().enumerate() {
                    if matches!(ext.extractor_type, crate::enums::ExtractorType::JsonPath)
                        && !is_valid_jsonpath_syntax(&ext.selector)
                    {
                        errors.push(ValidationError {
                            rule: "V-015".to_string(),
                            path: format!(
                                "{}.phases[{}].extractors[{}].selector",
                                actor_info.path_prefix, pi, ei
                            ),
                            message: format!("invalid JSONPath syntax: '{}'", ext.selector),
                        });
                    }
                }
            }
        }
    }
}

/// Basic JSONPath syntax validation.
/// Checks for balanced brackets, valid $ root, and structural correctness.
fn is_valid_jsonpath_syntax(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if !path.starts_with('$') {
        return false;
    }
    // Check balanced brackets
    let mut bracket_depth = 0i32;
    for ch in path.chars() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => {
                bracket_depth -= 1;
                if bracket_depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    if bracket_depth != 0 {
        return false;
    }
    // Check balanced parentheses
    let mut paren_depth = 0i32;
    for ch in path.chars() {
        match ch {
            '(' => paren_depth += 1,
            ')' => {
                paren_depth -= 1;
                if paren_depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    paren_depth == 0
}

// ─── V-016 ──────────────────────────────────────────────────────────────────

fn v016_template_syntax(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Check for unclosed {{ in template strings throughout the document
    // Handle single-phase form directly (collect_actors returns empty for it)
    if let Some(state) = &doc.attack.execution.state {
        check_templates_in_value(state, "attack.execution.state", errors);
    }
    // We check state values and on_enter action message fields
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                check_templates_in_value(
                    state,
                    &format!("{}.phases[{}].state", actor_info.path_prefix, pi),
                    errors,
                );
            }
        }
    }
}

fn check_templates_in_value(
    value: &serde_json::Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    match value {
        serde_json::Value::String(s) => {
            check_template_string(s, path, errors);
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                check_templates_in_value(v, &format!("{}[{}]", path, i), errors);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                check_templates_in_value(v, &format!("{}.{}", path, k), errors);
            }
        }
        _ => {}
    }
}

fn check_template_string(s: &str, path: &str, errors: &mut Vec<ValidationError>) {
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        // Skip escaped braces
        if i + 1 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'{' {
            i += 2;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Found opening {{, look for closing }}
            let start = i;
            i += 2;
            let mut found_close = false;
            while i + 1 < bytes.len() {
                if bytes[i] == b'}' && bytes[i + 1] == b'}' {
                    found_close = true;
                    i += 2;
                    break;
                }
                i += 1;
            }
            if !found_close {
                errors.push(ValidationError {
                    rule: "V-016".to_string(),
                    path: path.to_string(),
                    message: format!("unclosed template expression at position {}", start),
                });
            }
        } else {
            i += 1;
        }
    }
}

// ─── V-017 ──────────────────────────────────────────────────────────────────

fn v017_severity_confidence(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(severity) = &doc.attack.severity
        && let Severity::Object {
            confidence: Some(c),
            ..
        } = severity
        && (*c < 0 || *c > 100)
    {
        errors.push(ValidationError {
            rule: "V-017".to_string(),
            path: "attack.severity.confidence".to_string(),
            message: format!("severity.confidence must be 0-100, got {}", c),
        });
    }
}

// ─── V-018 ──────────────────────────────────────────────────────────────────

fn v018_surface_protocol(
    doc: &Document,
    errors: &mut Vec<ValidationError>,
    _warnings: &mut Vec<Diagnostic>,
) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            let protocol = ind
                .protocol
                .as_deref()
                .or_else(|| doc.attack.execution.mode.as_deref().map(extract_protocol))
                .or_else(|| {
                    // Multi-actor form: infer from single actor's mode
                    doc.attack.execution.actors.as_ref().and_then(|actors| {
                        if actors.len() == 1 {
                            Some(extract_protocol(&actors[0].mode))
                        } else {
                            None
                        }
                    })
                });
            if let Some(proto) = protocol
                && KNOWN_PROTOCOLS.contains(&proto)
                && let Some(entry) = lookup_surface(&ind.surface)
                && entry.protocol != proto
            {
                errors.push(ValidationError {
                    rule: "V-018".to_string(),
                    path: format!("attack.indicators[{}].surface", i),
                    message: format!(
                        "surface '{}' is for protocol '{}', but indicator targets '{}'",
                        ind.surface, entry.protocol, proto
                    ),
                });
            }
        }
    }
}

// ─── V-019 ──────────────────────────────────────────────────────────────────

fn v019_count_match_require_event(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(trigger) = &phase.trigger
                && trigger.event.is_none()
                && (trigger.count.is_some() || trigger.match_predicate.is_some())
            {
                errors.push(ValidationError {
                    rule: "V-019".to_string(),
                    path: format!("{}.phases[{}].trigger", actor_info.path_prefix, pi),
                    message: "trigger.count and trigger.match require event to be present"
                        .to_string(),
                });
            }
        }
    }
}

// ─── V-021 ──────────────────────────────────────────────────────────────────

fn v021_target_path_syntax(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(pattern) = &ind.pattern
                && let Some(target) = &pattern.target
                && !is_valid_wildcard_dot_path(target)
            {
                errors.push(ValidationError {
                    rule: "V-021".to_string(),
                    path: format!("attack.indicators[{}].pattern.target", i),
                    message: format!("invalid wildcard dot-path: '{}'", target),
                });
            }
            if let Some(semantic) = &ind.semantic
                && let Some(target) = &semantic.target
                && !is_valid_wildcard_dot_path(target)
            {
                errors.push(ValidationError {
                    rule: "V-021".to_string(),
                    path: format!("attack.indicators[{}].semantic.target", i),
                    message: format!("invalid wildcard dot-path: '{}'", target),
                });
            }
        }
    }
}

/// Validate wildcard dot-path syntax per §5.1.2.
///
/// Valid: `tools[*].description`, `content[*]`, `arguments`, `""`, `status.state`,
///        `2xx-status`, `0foo.bar`
///
/// Invalid: `tools[*.description` (missing bracket), `tools..name` (double dot),
///          `[*]tools` (leading bracket), `tools[*].[*]` (bracket after dot-bracket),
///          `tools[-1]` (negative index)
pub fn is_valid_wildcard_dot_path(path: &str) -> bool {
    if path.is_empty() {
        return true; // Empty string targets root
    }

    // Split on dots, but respect [*] as atomic suffix
    let segments = split_wildcard_path(path);
    if segments.is_none() {
        return false;
    }
    let segments = segments.unwrap();
    if segments.is_empty() {
        return false;
    }
    for seg in &segments {
        if seg.is_empty() {
            return false; // empty segment (double dot)
        }
    }
    true
}

/// Split a wildcard dot-path into segments, validating syntax.
/// Returns None if invalid.
fn split_wildcard_path(path: &str) -> Option<Vec<String>> {
    if path.is_empty() {
        return Some(vec![]);
    }

    let mut segments = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = path.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '.' => {
                if current.is_empty() && !segments.is_empty() {
                    // Double dot or leading dot after segment — check for trailing [*] on prev segment
                    return None;
                }
                if current.is_empty() && segments.is_empty() {
                    return None; // Leading dot
                }
                segments.push(current.clone());
                current.clear();
                i += 1;
            }
            '[' => {
                // Must be followed by * or digit(s) and ]
                if i + 2 < chars.len() && chars[i + 1] == '*' && chars[i + 2] == ']' {
                    current.push_str("[*]");
                    i += 3;
                    // After [*], must be followed by . or end
                    if i < chars.len() {
                        if chars[i] == '.' {
                            segments.push(current.clone());
                            current.clear();
                            i += 1;
                        } else {
                            return None; // Invalid char after [*]
                        }
                    }
                } else if i + 1 < chars.len() && chars[i + 1] == '-' {
                    return None; // Negative index
                } else {
                    return None; // Invalid bracket content
                }
            }
            c if is_path_segment_char(c) => {
                current.push(c);
                i += 1;
            }
            _ => {
                return None; // Invalid character
            }
        }
    }

    if !current.is_empty() {
        segments.push(current);
    } else if !segments.is_empty() {
        // Trailing dot
        return None;
    }

    // Validate that the path doesn't start with [
    if let Some(first) = segments.first()
        && first.starts_with('[')
    {
        return None;
    }

    Some(segments)
}

fn is_path_segment_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Validate simple dot-path syntax per §5.1.1.
/// No wildcards or numeric indices allowed.
pub fn is_valid_simple_dot_path(path: &str) -> bool {
    if path.is_empty() {
        return true; // Empty string targets root
    }

    let segments: Vec<&str> = path.split('.').collect();
    if segments.is_empty() {
        return false;
    }
    for seg in &segments {
        if seg.is_empty() {
            return false; // double dot or leading/trailing dot
        }
        // Each segment must be alphanumeric, underscores, hyphens
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return false;
        }
    }
    true
}

// ─── V-022 ──────────────────────────────────────────────────────────────────

fn v022_semantic_threshold(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(semantic) = &ind.semantic
                && let Some(threshold) = semantic.threshold
                && !(0.0..=1.0).contains(&threshold)
            {
                errors.push(ValidationError {
                    rule: "V-022".to_string(),
                    path: format!("attack.indicators[{}].semantic.threshold", i),
                    message: format!(
                        "semantic threshold must be in [0.0, 1.0], got {}",
                        threshold
                    ),
                });
            }
        }
    }
}

// ─── V-023 ──────────────────────────────────────────────────────────────────

fn v023_attack_id_format(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(id) = &doc.attack.id
        && !ATTACK_ID_RE.is_match(id)
    {
        errors.push(ValidationError {
            rule: "V-023".to_string(),
            path: "attack.id".to_string(),
            message: format!(
                "attack.id must match ^[A-Z][A-Z0-9-]*-[0-9]{{3,}}$, got '{}'",
                id
            ),
        });
    }
}

// ─── V-024 ──────────────────────────────────────────────────────────────────

fn v024_indicator_id_format(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(ind_id) = &ind.id
                && let Some(attack_id) = &doc.attack.id
            {
                if !INDICATOR_ID_RE.is_match(ind_id) {
                    errors.push(ValidationError {
                            rule: "V-024".to_string(),
                            path: format!("attack.indicators[{}].id", i),
                            message: format!(
                                "indicator.id must match ^[A-Z][A-Z0-9-]*-[0-9]{{3,}}-[0-9]{{2,}}$, got '{}'",
                                ind_id
                            ),
                        });
                } else {
                    // Prefix must equal attack.id
                    // The prefix is everything before the final -NN segment
                    if let Some(last_dash) = ind_id.rfind('-') {
                        let prefix = &ind_id[..last_dash];
                        if prefix != attack_id {
                            errors.push(ValidationError {
                                rule: "V-024".to_string(),
                                path: format!("attack.indicators[{}].id", i),
                                message: format!(
                                    "indicator.id prefix '{}' must equal attack.id '{}'",
                                    prefix, attack_id
                                ),
                            });
                        }
                    }
                }
            }
            // When attack.id is absent, indicator IDs are accepted without pattern constraints
        }
    }
}

// ─── V-025 ──────────────────────────────────────────────────────────────────

fn v025_indicator_confidence(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(conf) = ind.confidence
                && (!(0..=100).contains(&conf))
            {
                errors.push(ValidationError {
                    rule: "V-025".to_string(),
                    path: format!("attack.indicators[{}].confidence", i),
                    message: format!("indicator.confidence must be 0-100, got {}", conf),
                });
            }
        }
    }
}

// ─── V-026 ──────────────────────────────────────────────────────────────────

fn v026_expression_variables_paths(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(expr) = &ind.expression
                && let Some(vars) = &expr.variables
            {
                for (key, path) in vars {
                    if !is_valid_simple_dot_path(path) {
                        errors.push(ValidationError {
                                rule: "V-026".to_string(),
                                path: format!(
                                    "attack.indicators[{}].expression.variables.{}",
                                    i, key
                                ),
                                message: format!(
                                    "expression variable value must be a valid simple dot-path, got '{}'",
                                    path
                                ),
                            });
                    }
                }
            }
        }
    }
}

// ─── V-027 ──────────────────────────────────────────────────────────────────

fn v027_match_predicate_paths(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Check trigger.match keys
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(trigger) = &phase.trigger
                && let Some(pred) = &trigger.match_predicate
            {
                for key in pred.keys() {
                    if !is_valid_simple_dot_path(key) {
                        errors.push(ValidationError {
                            rule: "V-027".to_string(),
                            path: format!(
                                "{}.phases[{}].trigger.match.{}",
                                actor_info.path_prefix, pi, key
                            ),
                            message: format!(
                                "match predicate key must be a valid simple dot-path, got '{}'",
                                key
                            ),
                        });
                    }
                }
            }
        }
    }

    // Check response entry `when` predicate keys in state values
    // This is a deep check into state values which we do best-effort
    check_when_predicates_in_state(doc, errors);
}

fn check_when_predicates_in_state(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Handle single-phase form directly
    if let Some(state) = &doc.attack.execution.state {
        scan_when_predicates(state, "attack.execution.state", errors);
    }
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                scan_when_predicates(
                    state,
                    &format!("{}.phases[{}].state", actor_info.path_prefix, pi),
                    errors,
                );
            }
        }
    }
}

/// Walk a state value looking for response entries with `when` predicates
/// and validate that their keys are valid simple dot-paths.
fn scan_when_predicates(value: &serde_json::Value, path: &str, errors: &mut Vec<ValidationError>) {
    match value {
        serde_json::Value::Object(map) => {
            // Check if this object has a "when" key whose value is a map (predicate)
            if let Some(when_val) = map.get("when")
                && let Some(pred_map) = when_val.as_object()
            {
                for key in pred_map.keys() {
                    if !is_valid_simple_dot_path(key) {
                        errors.push(ValidationError {
                            rule: "V-027".to_string(),
                            path: format!("{}.when.{}", path, key),
                            message: format!(
                                "match predicate key must be a valid simple dot-path, got '{}'",
                                key
                            ),
                        });
                    }
                }
            }
            // Recurse into all values
            for (k, v) in map {
                scan_when_predicates(v, &format!("{}.{}", path, k), errors);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                scan_when_predicates(v, &format!("{}[{}]", path, i), errors);
            }
        }
        _ => {}
    }
}

// ─── V-028 ──────────────────────────────────────────────────────────────────

fn v028_conditional_requiredness(doc: &Document, errors: &mut Vec<ValidationError>) {
    let exec = &doc.attack.execution;

    // When execution.mode is absent and execution.actors is absent (mode-less multi-phase form)
    if exec.mode.is_none()
        && exec.actors.is_none()
        && let Some(phases) = &exec.phases
    {
        for (i, phase) in phases.iter().enumerate() {
            if phase.mode.is_none() {
                errors.push(ValidationError {
                    rule: "V-028".to_string(),
                    path: format!("attack.execution.phases[{}].mode", i),
                    message: "phase.mode is required when execution.mode is absent".to_string(),
                });
            }
        }
    }

    // When execution.mode is absent — indicators must specify protocol
    if exec.mode.is_none()
        && let Some(indicators) = &doc.attack.indicators
    {
        for (i, ind) in indicators.iter().enumerate() {
            if ind.protocol.is_none() {
                errors.push(ValidationError {
                    rule: "V-028".to_string(),
                    path: format!("attack.indicators[{}].protocol", i),
                    message: "indicator.protocol is required when execution.mode is absent"
                        .to_string(),
                });
            }
        }
    }
}

// ─── V-029 ──────────────────────────────────────────────────────────────────

fn v029_event_mode_validity(
    doc: &Document,
    errors: &mut Vec<ValidationError>,
    _warnings: &mut Vec<Diagnostic>,
) {
    for actor_info in collect_actors(doc) {
        let mode = match actor_info.mode {
            Some(m) => m,
            None => continue,
        };

        // Only validate for known modes
        if !KNOWN_MODES.contains(&mode) {
            continue;
        }

        for (pi, phase) in actor_info.phases.iter().enumerate() {
            let resolved_mode = phase.mode.as_deref().unwrap_or(mode);

            if !KNOWN_MODES.contains(&resolved_mode) {
                continue;
            }

            if let Some(trigger) = &phase.trigger
                && let Some(event) = &trigger.event
            {
                let base_event = strip_event_qualifier(event);
                if let Some(valid) = is_event_valid_for_mode(base_event, resolved_mode)
                    && !valid
                {
                    errors.push(ValidationError {
                        rule: "V-029".to_string(),
                        path: format!("{}.phases[{}].trigger.event", actor_info.path_prefix, pi),
                        message: format!(
                            "event '{}' is not valid for mode '{}'",
                            event, resolved_mode
                        ),
                    });
                }
                // If event not in registry, skip (unrecognized binding event)
            }
        }
    }
}

// ─── V-030 ──────────────────────────────────────────────────────────────────

fn v030_mutual_exclusion(doc: &Document, errors: &mut Vec<ValidationError>) {
    let exec = &doc.attack.execution;
    let has_state = exec.state.is_some();
    let has_phases = exec.phases.is_some();
    let has_actors = exec.actors.is_some();

    let count = [has_state, has_phases, has_actors]
        .iter()
        .filter(|&&b| b)
        .count();

    if count == 0 {
        errors.push(ValidationError {
            rule: "V-030".to_string(),
            path: "attack.execution".to_string(),
            message: "exactly one of state, phases, or actors must be present".to_string(),
        });
    } else if count > 1 {
        errors.push(ValidationError {
            rule: "V-030".to_string(),
            path: "attack.execution".to_string(),
            message: "state, phases, and actors are mutually exclusive".to_string(),
        });
    }

    // When state is present, mode must also be present
    if has_state && exec.mode.is_none() {
        errors.push(ValidationError {
            rule: "V-030".to_string(),
            path: "attack.execution.mode".to_string(),
            message: "execution.mode is required when execution.state is present".to_string(),
        });
    }
}

// ─── V-031 ──────────────────────────────────────────────────────────────────

fn v031_multi_actor_constraints(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(actors) = &doc.attack.execution.actors {
        let mut seen_names = std::collections::HashSet::new();

        for (i, actor) in actors.iter().enumerate() {
            // Unique names
            if !seen_names.insert(&actor.name) {
                errors.push(ValidationError {
                    rule: "V-031".to_string(),
                    path: format!("attack.execution.actors[{}].name", i),
                    message: format!("duplicate actor name: {}", actor.name),
                });
            }

            // Name pattern
            if !SNAKE_CASE_RE.is_match(&actor.name) {
                errors.push(ValidationError {
                    rule: "V-031".to_string(),
                    path: format!("attack.execution.actors[{}].name", i),
                    message: format!(
                        "actor name must match [a-z][a-z0-9_]*, got '{}'",
                        actor.name
                    ),
                });
            }

            // Mode required (already enforced by struct, but check empty)
            if actor.mode.is_empty() {
                errors.push(ValidationError {
                    rule: "V-031".to_string(),
                    path: format!("attack.execution.actors[{}].mode", i),
                    message: "actor must declare mode".to_string(),
                });
            }

            // At least one phase
            if actor.phases.is_empty() {
                errors.push(ValidationError {
                    rule: "V-031".to_string(),
                    path: format!("attack.execution.actors[{}].phases", i),
                    message: format!("actor '{}' must have at least one phase", actor.name),
                });
            }

            // Phase names unique within actor
            let mut phase_names = std::collections::HashSet::new();
            for (pi, phase) in actor.phases.iter().enumerate() {
                if let Some(name) = &phase.name
                    && !phase_names.insert(name.clone())
                {
                    errors.push(ValidationError {
                        rule: "V-031".to_string(),
                        path: format!("attack.execution.actors[{}].phases[{}].name", i, pi),
                        message: format!(
                            "duplicate phase name '{}' within actor '{}'",
                            name, actor.name
                        ),
                    });
                }
            }
        }
    }
}

// ─── V-032 ──────────────────────────────────────────────────────────────────

fn v032_cross_actor_refs(doc: &Document, errors: &mut Vec<ValidationError>) {
    let actor_names: std::collections::HashSet<String> =
        if let Some(actors) = &doc.attack.execution.actors {
            actors.iter().map(|a| a.name.clone()).collect()
        } else {
            // After normalization, single-phase/multi-phase have actor "default"
            let mut set = std::collections::HashSet::new();
            set.insert("default".to_string());
            set
        };

    // Scan all template strings in the document for {{actor_name.extractor_name}} references
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                check_cross_actor_refs_in_value(
                    state,
                    &actor_names,
                    &format!("{}.phases[{}].state", actor_info.path_prefix, pi),
                    errors,
                );
            }
        }
    }
}

fn check_cross_actor_refs_in_value(
    value: &serde_json::Value,
    actor_names: &std::collections::HashSet<String>,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    match value {
        serde_json::Value::String(s) => {
            check_cross_actor_refs_in_string(s, actor_names, path, errors);
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                check_cross_actor_refs_in_value(
                    v,
                    actor_names,
                    &format!("{}[{}]", path, i),
                    errors,
                );
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                check_cross_actor_refs_in_value(v, actor_names, &format!("{}.{}", path, k), errors);
            }
        }
        _ => {}
    }
}

fn check_cross_actor_refs_in_string(
    s: &str,
    actor_names: &std::collections::HashSet<String>,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    for cap in CROSS_ACTOR_REF_RE.captures_iter(s) {
        let actor_name = &cap[1];
        // Skip request.* and response.* references
        if actor_name == "request" || actor_name == "response" {
            continue;
        }
        if !actor_names.contains(actor_name) {
            errors.push(ValidationError {
                rule: "V-032".to_string(),
                path: path.to_string(),
                message: format!(
                    "cross-actor reference '{{{{{}}}}}' targets unknown actor '{}'",
                    &cap[0].trim_start_matches("{{").trim_end_matches("}}"),
                    actor_name
                ),
            });
        }
    }
}

// ─── V-033 ──────────────────────────────────────────────────────────────────

fn v033_content_synthesize_exclusivity(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Check state values for response entries with both content/messages and synthesize
    // Handle single-phase form directly
    if let Some(state) = &doc.attack.execution.state {
        let mode = doc.attack.execution.mode.as_deref().unwrap_or_default();
        check_response_exclusivity(state, mode, "attack.execution.state", errors);
    }
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                let mode = resolve_mode(doc, actor_info.mode, phase.mode.as_deref());
                let path = format!("{}.phases[{}].state", actor_info.path_prefix, pi);
                check_response_exclusivity(state, &mode.unwrap_or_default(), &path, errors);
            }
        }
    }
}

fn check_response_exclusivity(
    state: &serde_json::Value,
    _mode: &str,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(obj) = state.as_object() {
        // MCP tools responses
        if let Some(tools) = obj.get("tools").and_then(|v| v.as_array()) {
            for (ti, tool) in tools.iter().enumerate() {
                // Singular "response" form
                if let Some(resp) = tool.get("response") {
                    let has_content = resp.get("content").is_some();
                    let has_synthesize = resp.get("synthesize").is_some();
                    if has_content && has_synthesize {
                        errors.push(ValidationError {
                            rule: "V-033".to_string(),
                            path: format!("{}.tools[{}].response", path, ti),
                            message: "content and synthesize are mutually exclusive".to_string(),
                        });
                    }
                }
                // Plural "responses" form
                if let Some(responses) = tool.get("responses").and_then(|v| v.as_array()) {
                    for (ri, resp) in responses.iter().enumerate() {
                        let has_content = resp.get("content").is_some();
                        let has_synthesize = resp.get("synthesize").is_some();
                        if has_content && has_synthesize {
                            errors.push(ValidationError {
                                rule: "V-033".to_string(),
                                path: format!("{}.tools[{}].responses[{}]", path, ti, ri),
                                message: "content and synthesize are mutually exclusive"
                                    .to_string(),
                            });
                        }
                    }
                }
            }
        }

        // MCP prompts responses
        if let Some(prompts) = obj.get("prompts").and_then(|v| v.as_array()) {
            for (pi, prompt) in prompts.iter().enumerate() {
                if let Some(responses) = prompt.get("responses").and_then(|v| v.as_array()) {
                    for (ri, resp) in responses.iter().enumerate() {
                        let has_messages = resp.get("messages").is_some();
                        let has_synthesize = resp.get("synthesize").is_some();
                        if has_messages && has_synthesize {
                            errors.push(ValidationError {
                                rule: "V-033".to_string(),
                                path: format!("{}.prompts[{}].responses[{}]", path, pi, ri),
                                message: "messages and synthesize are mutually exclusive"
                                    .to_string(),
                            });
                        }
                    }
                }
            }
        }

        // A2A task_responses
        if let Some(task_responses) = obj.get("task_responses").and_then(|v| v.as_array()) {
            for (ri, resp) in task_responses.iter().enumerate() {
                let has_messages = resp.get("messages").is_some();
                let has_artifacts = resp.get("artifacts").is_some();
                let has_synthesize = resp.get("synthesize").is_some();
                if (has_messages || has_artifacts) && has_synthesize {
                    errors.push(ValidationError {
                        rule: "V-033".to_string(),
                        path: format!("{}.task_responses[{}]", path, ri),
                        message: "messages/artifacts and synthesize are mutually exclusive"
                            .to_string(),
                    });
                }
            }
        }

        // AG-UI run_agent_input
        if let Some(rai) = obj.get("run_agent_input") {
            let has_messages = rai.get("messages").is_some();
            let has_synthesize = rai.get("synthesize").is_some();
            if has_messages && has_synthesize {
                errors.push(ValidationError {
                    rule: "V-033".to_string(),
                    path: format!("{}.run_agent_input", path),
                    message: "messages and synthesize are mutually exclusive".to_string(),
                });
            }
        }
    }
}

// ─── V-034 ──────────────────────────────────────────────────────────────────

fn v034_catch_all_constraints(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Handle single-phase form directly
    if let Some(state) = &doc.attack.execution.state {
        check_catch_all_in_state(state, "attack.execution.state", errors);
    }
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                let path = format!("{}.phases[{}].state", actor_info.path_prefix, pi);
                check_catch_all_in_state(state, &path, errors);
            }
        }
    }
}

fn check_catch_all_in_state(
    state: &serde_json::Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(obj) = state.as_object() {
        // MCP tools responses
        if let Some(tools) = obj.get("tools").and_then(|v| v.as_array()) {
            for (ti, tool) in tools.iter().enumerate() {
                if let Some(responses) = tool.get("responses").and_then(|v| v.as_array()) {
                    check_catch_all_list(
                        responses,
                        &format!("{}.tools[{}].responses", path, ti),
                        errors,
                    );
                }
            }
        }

        // MCP prompts responses
        if let Some(prompts) = obj.get("prompts").and_then(|v| v.as_array()) {
            for (pi2, prompt) in prompts.iter().enumerate() {
                if let Some(responses) = prompt.get("responses").and_then(|v| v.as_array()) {
                    check_catch_all_list(
                        responses,
                        &format!("{}.prompts[{}].responses", path, pi2),
                        errors,
                    );
                }
            }
        }

        // A2A task_responses
        if let Some(task_responses) = obj.get("task_responses").and_then(|v| v.as_array()) {
            check_catch_all_list(task_responses, &format!("{}.task_responses", path), errors);
        }
    }
}

fn check_catch_all_list(
    entries: &[serde_json::Value],
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    let mut catch_all_count = 0;
    for entry in entries {
        // Absent `when` or explicit `when: null` both mean catch-all
        match entry.get("when") {
            None | Some(serde_json::Value::Null) => catch_all_count += 1,
            _ => {}
        }
    }
    if catch_all_count > 1 {
        errors.push(ValidationError {
            rule: "V-034".to_string(),
            path: path.to_string(),
            message: format!(
                "at most one entry may omit 'when' (catch-all), found {}",
                catch_all_count
            ),
        });
    }
}

// ─── V-035 ──────────────────────────────────────────────────────────────────

fn v035_synthesize_prompt(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Handle single-phase form directly
    if let Some(state) = &doc.attack.execution.state {
        check_synthesize_prompts(state, "attack.execution.state", errors);
    }
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                let path = format!("{}.phases[{}].state", actor_info.path_prefix, pi);
                check_synthesize_prompts(state, &path, errors);
            }
        }
    }
}

fn check_synthesize_prompts(
    value: &serde_json::Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(synth) = map.get("synthesize")
                && let Some(synth_obj) = synth.as_object()
            {
                match synth_obj.get("prompt") {
                    Some(serde_json::Value::String(s)) if s.is_empty() => {
                        errors.push(ValidationError {
                            rule: "V-035".to_string(),
                            path: format!("{}.synthesize.prompt", path),
                            message: "synthesize.prompt must be non-empty".to_string(),
                        });
                    }
                    None => {
                        errors.push(ValidationError {
                            rule: "V-035".to_string(),
                            path: format!("{}.synthesize.prompt", path),
                            message: "synthesize.prompt must be present".to_string(),
                        });
                    }
                    _ => {}
                }
            }
            for (k, v) in map {
                if k != "synthesize" {
                    check_synthesize_prompts(v, &format!("{}.{}", path, k), errors);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                check_synthesize_prompts(v, &format!("{}[{}]", path, i), errors);
            }
        }
        _ => {}
    }
}

// ─── V-036 ──────────────────────────────────────────────────────────────────

fn v036_mode_protocol_pattern(
    doc: &Document,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<Diagnostic>,
) {
    // execution.mode pattern is validated by V-005; V-036 handles actor/phase modes.
    // Check for W-002 warning on execution.mode (unrecognized but valid pattern)
    if let Some(mode) = &doc.attack.execution.mode
        && MODE_RE.is_match(mode)
        && !KNOWN_MODES.contains(&mode.as_str())
    {
        warnings.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "W-002".to_string(),
            path: Some("attack.execution.mode".to_string()),
            message: format!("unrecognized mode: '{}'", mode),
        });
    }

    // Check actor modes
    if let Some(actors) = &doc.attack.execution.actors {
        for (i, actor) in actors.iter().enumerate() {
            if !MODE_RE.is_match(&actor.mode) {
                errors.push(ValidationError {
                    rule: "V-036".to_string(),
                    path: format!("attack.execution.actors[{}].mode", i),
                    message: format!(
                        "mode must match [a-z][a-z0-9_]*_(server|client), got '{}'",
                        actor.mode
                    ),
                });
            } else if !KNOWN_MODES.contains(&actor.mode.as_str()) {
                warnings.push(Diagnostic {
                    severity: DiagnosticSeverity::Warning,
                    code: "W-002".to_string(),
                    path: Some(format!("attack.execution.actors[{}].mode", i)),
                    message: format!("unrecognized mode: '{}'", actor.mode),
                });
            }
        }
    }

    // Check phase modes
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(mode) = &phase.mode
                && !MODE_RE.is_match(mode)
            {
                errors.push(ValidationError {
                    rule: "V-036".to_string(),
                    path: format!("{}.phases[{}].mode", actor_info.path_prefix, pi),
                    message: format!(
                        "mode must match [a-z][a-z0-9_]*_(server|client), got '{}'",
                        mode
                    ),
                });
            }
        }
    }

    // Check indicator protocols
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(protocol) = &ind.protocol {
                if !PROTOCOL_RE.is_match(protocol) {
                    errors.push(ValidationError {
                        rule: "V-036".to_string(),
                        path: format!("attack.indicators[{}].protocol", i),
                        message: format!("protocol must match [a-z][a-z0-9_]*, got '{}'", protocol),
                    });
                } else if !KNOWN_PROTOCOLS.contains(&protocol.as_str()) {
                    warnings.push(Diagnostic {
                        severity: DiagnosticSeverity::Warning,
                        code: "W-003".to_string(),
                        path: Some(format!("attack.indicators[{}].protocol", i)),
                        message: format!("unrecognized protocol: '{}'", protocol),
                    });
                }
            }
        }
    }
}

// ─── V-037 ──────────────────────────────────────────────────────────────────

fn v037_version_positive(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(version) = doc.attack.version
        && version < 1
    {
        errors.push(ValidationError {
            rule: "V-037".to_string(),
            path: "attack.version".to_string(),
            message: format!(
                "attack.version must be a positive integer (>= 1), got {}",
                version
            ),
        });
    }
}

// ─── V-038 ──────────────────────────────────────────────────────────────────

fn v038_trigger_after_duration(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Validate trigger.after durations
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(trigger) = &phase.trigger
                && let Some(after) = &trigger.after
                && !is_valid_duration(after)
            {
                errors.push(ValidationError {
                    rule: "V-038".to_string(),
                    path: format!("{}.phases[{}].trigger.after", actor_info.path_prefix, pi),
                    message: format!("invalid duration: '{}'", after),
                });
            }
        }
    }

    // Validate attack.grace_period duration
    if let Some(gp) = &doc.attack.grace_period
        && !is_valid_duration(gp)
    {
        errors.push(ValidationError {
            rule: "V-038".to_string(),
            path: "attack.grace_period".to_string(),
            message: format!("invalid duration: '{}'", gp),
        });
    }
}

/// Validate a duration string (shorthand or ISO 8601).
pub fn is_valid_duration(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if SHORTHAND_DURATION_RE.is_match(s) {
        return true;
    }
    if ISO_DURATION_RE.is_match(s) {
        // Must have at least one component
        let has_day = s.contains('D');
        let has_t = s.contains('T');
        let has_time_component = s.contains('H') || s.contains('M') || s.contains('S');
        // If T is present, it must have at least one time component (reject "P1DT", "PT")
        if has_t && !has_time_component {
            return false;
        }
        return has_day || has_time_component;
    }
    false
}

// ─── V-039 ──────────────────────────────────────────────────────────────────

fn v039_extractor_name_pattern(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(extractors) = &phase.extractors {
                for (ei, ext) in extractors.iter().enumerate() {
                    if !SNAKE_CASE_RE.is_match(&ext.name) {
                        errors.push(ValidationError {
                            rule: "V-039".to_string(),
                            path: format!(
                                "{}.phases[{}].extractors[{}].name",
                                actor_info.path_prefix, pi, ei
                            ),
                            message: format!(
                                "extractor name must match [a-z][a-z0-9_]*, got '{}'",
                                ext.name
                            ),
                        });
                    }
                }
            }
        }
    }
}

// ─── V-040 ──────────────────────────────────────────────────────────────────

fn v040_extractors_non_empty(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(extractors) = &phase.extractors
                && extractors.is_empty()
            {
                errors.push(ValidationError {
                    rule: "V-040".to_string(),
                    path: format!("{}.phases[{}].extractors", actor_info.path_prefix, pi),
                    message: "extractors, when present, must contain at least one entry"
                        .to_string(),
                });
            }
        }
    }
}

// ─── V-041 ──────────────────────────────────────────────────────────────────

fn v041_expression_variable_keys(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(expr) = &ind.expression
                && let Some(vars) = &expr.variables
            {
                for key in vars.keys() {
                    if !CEL_ID_RE.is_match(key) {
                        errors.push(ValidationError {
                            rule: "V-041".to_string(),
                            path: format!("attack.indicators[{}].expression.variables.{}", i, key),
                            message: format!(
                                "expression variable key must be a valid CEL identifier, got '{}'",
                                key
                            ),
                        });
                    }
                }
            }
        }
    }
}

// ─── V-042 ──────────────────────────────────────────────────────────────────

fn v042_trigger_event_or_after(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(trigger) = &phase.trigger
                && trigger.event.is_none()
                && trigger.after.is_none()
            {
                errors.push(ValidationError {
                    rule: "V-042".to_string(),
                    path: format!("{}.phases[{}].trigger", actor_info.path_prefix, pi),
                    message: "trigger must specify at least one of event or after".to_string(),
                });
            }
        }
    }
}

// ─── V-043 ──────────────────────────────────────────────────────────────────

fn v043_binding_specific_action_keys(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(actions) = &phase.on_enter {
                for (ai, action) in actions.iter().enumerate() {
                    let count = match action {
                        Action::SendNotification {
                            non_ext_key_count, ..
                        }
                        | Action::Log {
                            non_ext_key_count, ..
                        }
                        | Action::SendElicitation {
                            non_ext_key_count, ..
                        }
                        | Action::BindingSpecific {
                            non_ext_key_count, ..
                        } => *non_ext_key_count,
                    };
                    if count != 1 {
                        errors.push(ValidationError {
                            rule: "V-043".to_string(),
                            path: format!(
                                "{}.phases[{}].on_enter[{}]",
                                actor_info.path_prefix, pi, ai
                            ),
                            message: format!(
                                "action must have exactly one non-extension key, found {}",
                                count
                            ),
                        });
                    }
                }
            }
        }
    }
}

// ─── V-044 ──────────────────────────────────────────────────────────────────

fn v044_regex_extractor_capture_group(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(extractors) = &phase.extractors {
                for (ei, ext) in extractors.iter().enumerate() {
                    if ext.extractor_type == crate::enums::ExtractorType::Regex {
                        // Check that the selector contains at least one capture group
                        if !has_capture_group(&ext.selector) {
                            errors.push(ValidationError {
                                rule: "V-044".to_string(),
                                path: format!(
                                    "{}.phases[{}].extractors[{}].selector",
                                    actor_info.path_prefix, pi, ei
                                ),
                                message: "regex extractor selector must contain at least one capture group".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Check if a regex pattern contains at least one unescaped capture group.
fn has_capture_group(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip escaped character
            continue;
        }
        if bytes[i] == b'(' && (i + 1 >= bytes.len() || bytes[i + 1] != b'?') {
            return true;
        }
        i += 1;
    }
    false
}

// ─── V-045 ──────────────────────────────────────────────────────────────────

fn v045_on_enter_non_empty(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(actions) = &phase.on_enter
                && actions.is_empty()
            {
                errors.push(ValidationError {
                    rule: "V-045".to_string(),
                    path: format!("{}.phases[{}].on_enter", actor_info.path_prefix, pi),
                    message: "on_enter, when present, must contain at least one action".to_string(),
                });
            }
        }
    }
}

// ─── W-001 ──────────────────────────────────────────────────────────────────

fn w001_oatf_key_ordering(doc: &Document, warnings: &mut Vec<Diagnostic>) {
    if !doc.oatf_is_first_key {
        warnings.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            code: "W-001".to_string(),
            path: Some("oatf".to_string()),
            message: "oatf key should be the first key in the document".to_string(),
        });
    }
}

// ─── W-004 ──────────────────────────────────────────────────────────────────

fn w004_undeclared_extractor_refs(doc: &Document, warnings: &mut Vec<Diagnostic>) {
    // Collect actor names so cross-actor references ({{actor.extractor}}) are not flagged
    let actor_names: std::collections::HashSet<String> =
        if let Some(actors) = &doc.attack.execution.actors {
            actors.iter().map(|a| a.name.clone()).collect()
        } else {
            let mut set = std::collections::HashSet::new();
            set.insert("default".to_string());
            set
        };

    for actor_info in collect_actors(doc) {
        for phase in actor_info.phases.iter() {
            let declared: std::collections::HashSet<String> = phase
                .extractors
                .as_ref()
                .map(|exts| exts.iter().map(|e| e.name.clone()).collect())
                .unwrap_or_default();

            let mut has_undeclared = false;

            // Check state for template references
            if let Some(state) = &phase.state {
                has_undeclared |= check_undeclared_refs_in_value(state, &declared, &actor_names);
            }

            // Check on_enter actions for template references
            if let Some(actions) = &phase.on_enter {
                for action in actions {
                    let action_value = serde_json::to_value(action).unwrap_or_default();
                    has_undeclared |=
                        check_undeclared_refs_in_value(&action_value, &declared, &actor_names);
                }
            }

            if has_undeclared {
                warnings.push(Diagnostic {
                    severity: DiagnosticSeverity::Warning,
                    code: "W-004".to_string(),
                    path: None,
                    message: "template references undeclared extractor".to_string(),
                });
                return; // Emit once per document
            }
        }
    }
}

fn check_undeclared_refs_in_value(
    value: &serde_json::Value,
    declared: &std::collections::HashSet<String>,
    actor_names: &std::collections::HashSet<String>,
) -> bool {
    match value {
        serde_json::Value::String(s) => {
            for cap in TEMPLATE_VAR_RE.captures_iter(s) {
                let var_name = &cap[1];
                // Get the root (before any dot)
                let root = var_name.split('.').next().unwrap_or(var_name);
                // Skip request/response builtins and cross-actor references
                if root == "request" || root == "response" || actor_names.contains(root) {
                    continue;
                }
                if !declared.contains(root) {
                    return true;
                }
            }
            false
        }
        serde_json::Value::Array(arr) => arr
            .iter()
            .any(|v| check_undeclared_refs_in_value(v, declared, actor_names)),
        serde_json::Value::Object(map) => map
            .values()
            .any(|v| check_undeclared_refs_in_value(v, declared, actor_names)),
        _ => false,
    }
}

// ─── W-005 ──────────────────────────────────────────────────────────────────

fn w005_indicator_protocol_mismatch(doc: &Document, warnings: &mut Vec<Diagnostic>) {
    // Collect all protocols used by actors
    let mut actor_protocols: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some(mode) = &doc.attack.execution.mode {
        actor_protocols.insert(extract_protocol(mode).to_string());
    }
    if let Some(actors) = &doc.attack.execution.actors {
        for actor in actors {
            actor_protocols.insert(extract_protocol(&actor.mode).to_string());
        }
    }
    // Also check phase modes
    for actor_info in collect_actors(doc) {
        for phase in actor_info.phases {
            if let Some(mode) = &phase.mode {
                actor_protocols.insert(extract_protocol(mode).to_string());
            }
        }
    }

    if actor_protocols.is_empty() {
        return;
    }

    if let Some(indicators) = &doc.attack.indicators {
        for ind in indicators {
            if let Some(protocol) = &ind.protocol
                && !actor_protocols.contains(protocol.as_str())
            {
                warnings.push(Diagnostic {
                    severity: DiagnosticSeverity::Warning,
                    code: "W-005".to_string(),
                    path: None,
                    message: format!(
                        "indicator protocol '{}' does not match any actor protocol",
                        protocol
                    ),
                });
                return; // Emit once per document
            }
        }
    }
}
