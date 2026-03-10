//! Document validation against conformance rules V-001 through V-050.
//!
//! Returns **all** errors and warnings, not just the first. Validation does not
//! modify the document.

use crate::error::*;
use crate::event_registry::{
    extract_protocol, infer_execution_protocol, is_event_valid_for_mode, strip_event_qualifier,
};
use crate::primitives::{compile_user_regex, is_valid_simple_dot_path, is_valid_wildcard_dot_path};
use crate::surface::{KNOWN_MODES, KNOWN_PROTOCOLS, lookup_surface};
use crate::types::*;
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

const MAX_VALUE_DEPTH: usize = 128;

// ─── Helper: construct ValidationError with auto-populated spec_ref ─────────

fn verr(rule: &str, path: impl Into<String>, message: impl Into<String>) -> ValidationError {
    ValidationError {
        rule: rule.to_string(),
        spec_ref: spec_ref_for_rule(rule).to_string(),
        path: path.into(),
        message: message.into(),
    }
}

fn spec_ref_for_rule(rule: &str) -> &'static str {
    match rule {
        "V-001" => "§11.1.1",
        "V-002" => "§11.1.2",
        "V-003" => "§11.1.3",
        "V-004" => "§11.1.4",
        "V-005" => "§11.1.5",
        "V-006" => "§11.1.6",
        "V-007" => "§11.1.8",
        "V-008" => "§11.1.8",
        "V-009" => "§11.1.8",
        "V-010" => "§11.1.10",
        "V-011" => "§11.1.8",
        "V-012" => "§11.1.11",
        "V-013" => "§5.7",
        "V-014" => "§5.7",
        "V-015" => "§5.7",
        "V-016" => "§5.7",
        "V-017" => "§4.3",
        "V-018" => "§7",
        "V-019" => "§5.3",
        "V-020" => "§11.1.1",
        "V-021" => "§6.2",
        "V-022" => "§6.4",
        "V-023" => "§4.2",
        "V-024" => "§6.1",
        "V-025" => "§6.1",
        "V-026" => "§6.3",
        "V-027" => "§5.4",
        "V-028" => "§5.1",
        "V-029" => "§7",
        "V-030" => "§5.1",
        "V-031" => "§5.1",
        "V-032" => "§5.5",
        "V-033" => "§11.1.14",
        "V-034" => "§11.1.15",
        "V-035" => "§11.1.16",
        "V-036" => "§5.1",
        "V-037" => "§4.2",
        "V-038" => "§5.3",
        "V-039" => "§5.5",
        "V-040" => "§11.1.8",
        "V-041" => "§11.1.17",
        "V-042" => "§5.2",
        "V-043" => "§5.2",
        "V-044" => "§5.5",
        "V-045" => "§5.2",
        "V-046" => "§4.2",
        "V-047" => "§7.2",
        "V-048" => "§4.4",
        "V-049" => "§4.2",
        "V-050" => "§4.5",
        _ => "",
    }
}

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

static PROTOCOL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]*$").unwrap());

/// Validate a parsed document against all conformance rules (V-001..V-046).
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
    check_state_is_object(doc, &mut errors);
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
    // V-043 is enforced at parse time (Action::deserialize rejects != 1 non-extension key).
    v044_regex_extractor_capture_group(doc, &mut errors);
    v045_on_enter_non_empty(doc, &mut errors);
    v046_phase_mode_matches_actor(doc, &mut errors);
    v047_a2a_client_mutual_exclusivity(doc, &mut errors);
    v048_impact_no_duplicates(doc, &mut errors);
    v049_grace_period_duration(doc, &mut errors);
    v050_correlation_requires_indicators(doc, &mut errors);

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

fn collect_actor_names(doc: &Document) -> std::collections::HashSet<String> {
    if let Some(actors) = &doc.attack.execution.actors {
        actors.iter().map(|a| a.name.clone()).collect()
    } else {
        std::iter::once("default".to_string()).collect()
    }
}

// ─── V-001 ──────────────────────────────────────────────────────────────────

fn v001_oatf_version(doc: &Document, errors: &mut Vec<ValidationError>) {
    if doc.oatf != "0.1" {
        errors.push(verr(
            "V-001",
            "oatf",
            format!("oatf field must be '0.1', got '{}'", doc.oatf),
        ));
    }
}

// ─── V-005 ──────────────────────────────────────────────────────────────────

fn v005_enum_values(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Validate elicitation_responses action enum in state
    let check_elicitation_responses =
        |state: &Value, path_prefix: &str, errors: &mut Vec<ValidationError>| {
            if let Some(entries) = state
                .get("elicitation_responses")
                .and_then(|v| v.as_array())
            {
                static VALID_ELICITATION_ACTIONS: &[&str] = &["accept", "decline", "cancel"];
                for (ei, entry) in entries.iter().enumerate() {
                    if let Some(action_val) = entry.get("action") {
                        match action_val.as_str() {
                            Some(action) if VALID_ELICITATION_ACTIONS.contains(&action) => {}
                            Some(action) => {
                                errors.push(verr(
                                "V-005",
                                format!("{}.elicitation_responses[{}].action", path_prefix, ei),
                                format!(
                                    "invalid elicitation_responses action: '{}', must be one of: accept, decline, cancel",
                                    action
                                ),
                            ));
                            }
                            None => {
                                errors.push(verr(
                                    "V-005",
                                    format!("{}.elicitation_responses[{}].action", path_prefix, ei),
                                    format!(
                                        "elicitation_responses action must be a string, got {}",
                                        action_val
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        };

    // Check execution.state
    if let Some(state) = &doc.attack.execution.state {
        check_elicitation_responses(state, "attack.execution.state", errors);
    }
    // Check phase states
    if let Some(phases) = &doc.attack.execution.phases {
        for (pi, phase) in phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                check_elicitation_responses(
                    state,
                    &format!("attack.execution.phases[{}].state", pi),
                    errors,
                );
            }
        }
    }
    // Check actor phase states
    if let Some(actors) = &doc.attack.execution.actors {
        for (ai, actor) in actors.iter().enumerate() {
            for (pi, phase) in actor.phases.iter().enumerate() {
                if let Some(state) = &phase.state {
                    check_elicitation_responses(
                        state,
                        &format!("attack.execution.actors[{}].phases[{}].state", ai, pi),
                        errors,
                    );
                }
            }
        }
    }
}

// ─── V-006 ──────────────────────────────────────────────────────────────────

fn v006_indicators_non_empty(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators
        && indicators.is_empty()
    {
        errors.push(verr(
            "V-006",
            "attack.indicators",
            "indicators, when present, must contain at least one entry",
        ));
    }
}

// ─── V-007 ──────────────────────────────────────────────────────────────────

fn v007_phases_non_empty(doc: &Document, errors: &mut Vec<ValidationError>) {
    let exec = &doc.attack.execution;
    if let Some(phases) = &exec.phases
        && phases.is_empty()
    {
        errors.push(verr(
            "V-007",
            "attack.execution.phases",
            "phases must contain at least one entry",
        ));
    }
    if let Some(actors) = &exec.actors {
        for (i, actor) in actors.iter().enumerate() {
            if actor.phases.is_empty() {
                errors.push(verr(
                    "V-007",
                    format!("attack.execution.actors[{}].phases", i),
                    format!("actor '{}' must have at least one phase", actor.name),
                ));
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
            errors.push(verr(
                "V-008",
                format!("{}.phases", actor_info.path_prefix),
                format!(
                    "at most one terminal phase (no trigger) per actor, found {}",
                    terminal_count
                ),
            ));
        }
        if let Some(idx) = last_terminal_idx
            && idx != actor_info.phases.len() - 1
        {
            errors.push(verr(
                "V-008",
                format!("{}.phases[{}]", actor_info.path_prefix, idx),
                "terminal phase must be the last phase in the actor's list",
            ));
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
        errors.push(verr(
            "V-009",
            "attack.execution.phases[0]",
            "first phase must include state",
        ));
    }
    if let Some(actors) = &exec.actors {
        for (i, actor) in actors.iter().enumerate() {
            if !actor.phases.is_empty() && actor.phases[0].state.is_none() {
                errors.push(verr(
                    "V-009",
                    format!("attack.execution.actors[{}].phases[0]", i),
                    format!("first phase of actor '{}' must include state", actor.name),
                ));
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
                errors.push(verr(
                    "V-010",
                    format!("attack.indicators[{}].id", i),
                    format!("duplicate indicator id: {}", id),
                ));
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
                errors.push(verr(
                    "V-011",
                    format!("{}.phases[{}].name", actor_info.path_prefix, i),
                    format!("duplicate phase name: {}", name),
                ));
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
                errors.push(verr(
                    "V-012",
                    format!("attack.indicators[{}]", i),
                    format!(
                        "each indicator must have exactly one detection key (pattern, expression, or semantic), found {}",
                        count
                    ),
                ));
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
                errors.push(verr(
                        "V-012",
                        format!("attack.indicators[{}].pattern", i),
                        "pattern must not have both 'condition' and shorthand operator fields (contains, regex, etc.)",
                    ));
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
                    && let Err(e) = compile_user_regex(re)
                {
                    errors.push(verr(
                        "V-013",
                        format!("attack.indicators[{}].pattern.regex", i),
                        format!("invalid regex: {}", e),
                    ));
                }
                // Check regex in condition form
                if let Some(Condition::Operators(cond)) = &pattern.condition
                    && let Some(re) = &cond.regex
                    && let Err(e) = compile_user_regex(re)
                {
                    errors.push(verr(
                        "V-013",
                        format!("attack.indicators[{}].pattern.condition.regex", i),
                        format!("invalid regex: {}", e),
                    ));
                }
            }
        }
    }
    // Also check regex in match predicates (triggers and response entries)
    validate_regex_in_phases(doc, errors);
    validate_regex_in_state_when_predicates(doc, errors);
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
                        && let Err(e) = compile_user_regex(re)
                    {
                        errors.push(verr(
                            "V-013",
                            format!(
                                "{}.phases[{}].trigger.match.{}.regex",
                                actor_info.path_prefix, pi, key
                            ),
                            format!("invalid regex: {}", e),
                        ));
                    }
                }
            }
        }
    }
}

/// §2.7: state uses Value for diagnostic reporting but validation rejects non-object values.
fn check_state_is_object(doc: &Document, errors: &mut Vec<ValidationError>) {
    for_each_state(doc, |state, path| {
        if !state.is_object() {
            errors.push(verr(
                "state-type",
                path,
                format!(
                    "state must be a YAML mapping (object), got {}",
                    json_type_name(state)
                ),
            ));
        }
    });
}

fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn for_each_state<F>(doc: &Document, mut visit: F)
where
    F: FnMut(&serde_json::Value, &str),
{
    if let Some(state) = &doc.attack.execution.state {
        visit(state, "attack.execution.state");
    }
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                visit(
                    state,
                    &format!("{}.phases[{}].state", actor_info.path_prefix, pi),
                );
            }
        }
    }
}

fn for_each_state_response_entry<F>(doc: &Document, mut visit: F)
where
    F: FnMut(&serde_json::Value, &str),
{
    for_each_state(doc, |state, path| {
        for_each_response_entry_in_state(state, path, &mut visit);
    });
}

fn for_each_response_entry_in_state<F>(state: &serde_json::Value, path: &str, visit: &mut F)
where
    F: FnMut(&serde_json::Value, &str),
{
    let Some(obj) = state.as_object() else {
        return;
    };

    if let Some(tools) = obj.get("tools").and_then(|v| v.as_array()) {
        for (ti, tool) in tools.iter().enumerate() {
            if let Some(responses) = tool.get("responses").and_then(|v| v.as_array()) {
                for (ri, entry) in responses.iter().enumerate() {
                    visit(entry, &format!("{}.tools[{}].responses[{}]", path, ti, ri));
                }
            }
        }
    }

    if let Some(prompts) = obj.get("prompts").and_then(|v| v.as_array()) {
        for (pi, prompt) in prompts.iter().enumerate() {
            if let Some(responses) = prompt.get("responses").and_then(|v| v.as_array()) {
                for (ri, entry) in responses.iter().enumerate() {
                    visit(
                        entry,
                        &format!("{}.prompts[{}].responses[{}]", path, pi, ri),
                    );
                }
            }
        }
    }

    if let Some(task_responses) = obj.get("task_responses").and_then(|v| v.as_array()) {
        for (ri, entry) in task_responses.iter().enumerate() {
            visit(entry, &format!("{}.task_responses[{}]", path, ri));
        }
    }

    if let Some(sampling) = obj.get("sampling_responses").and_then(|v| v.as_array()) {
        for (ri, entry) in sampling.iter().enumerate() {
            visit(entry, &format!("{}.sampling_responses[{}]", path, ri));
        }
    }
}

fn validate_regex_in_state_when_predicates(doc: &Document, errors: &mut Vec<ValidationError>) {
    for_each_state_response_entry(doc, |entry, path| {
        if let Some(when_val) = entry.get("when")
            && let Some(pred_map) = when_val.as_object()
        {
            for (key, pred_entry) in pred_map {
                if let Some(entry_obj) = pred_entry.as_object()
                    && let Some(re_val) = entry_obj.get("regex")
                    && let Some(re) = re_val.as_str()
                    && let Err(e) = compile_user_regex(re)
                {
                    errors.push(verr(
                        "V-013",
                        format!("{}.when.{}.regex", path, key),
                        format!("invalid regex: {}", e),
                    ));
                }
            }
        }
    });
}

// ─── V-014 ──────────────────────────────────────────────────────────────────

fn v014_cel_valid(doc: &Document, errors: &mut Vec<ValidationError>) {
    #[cfg(feature = "cel-validate")]
    {
        if let Some(indicators) = &doc.attack.indicators {
            for (i, ind) in indicators.iter().enumerate() {
                if let Some(expr) = &ind.expression {
                    // Try to compile the CEL expression
                    if let Err(e) = cel::Program::compile(&expr.cel) {
                        errors.push(verr(
                            "V-014",
                            format!("attack.indicators[{}].expression.cel", i),
                            format!("invalid CEL expression: {}", e),
                        ));
                    }
                }
            }
        }
    }

    #[cfg(not(feature = "cel-validate"))]
    {
        let _ = (doc, errors);
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
                        errors.push(verr(
                            "V-015",
                            format!(
                                "{}.phases[{}].extractors[{}].selector",
                                actor_info.path_prefix, pi, ei
                            ),
                            format!("invalid JSONPath syntax: '{}'", ext.selector),
                        ));
                    }
                }
            }
        }
    }
}

/// JSONPath syntax validation using the serde_json_path parser (RFC 9535).
fn is_valid_jsonpath_syntax(path: &str) -> bool {
    serde_json_path::JsonPath::parse(path).is_ok()
}

// ─── V-016 ──────────────────────────────────────────────────────────────────

fn v016_template_syntax(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Check for unclosed {{ in template strings throughout the document
    for_each_state(doc, |state, path| {
        check_templates_in_value(state, path, errors, 0);
    });
    // Also check on_enter action message fields
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(actions) = &phase.on_enter {
                for (ai, action) in actions.iter().enumerate() {
                    let action_value = serde_json::to_value(action).unwrap_or_default();
                    check_templates_in_value(
                        &action_value,
                        &format!("{}.phases[{}].on_enter[{}]", actor_info.path_prefix, pi, ai),
                        errors,
                        0,
                    );
                }
            }
        }
    }
}

fn check_templates_in_value(
    value: &serde_json::Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    depth: usize,
) {
    if depth > MAX_VALUE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            check_template_string(s, path, errors);
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                check_templates_in_value(v, &format!("{}[{}]", path, i), errors, depth + 1);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                check_templates_in_value(v, &format!("{}.{}", path, k), errors, depth + 1);
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
                errors.push(verr(
                    "V-016",
                    path.to_string(),
                    format!("unclosed template expression at position {}", start),
                ));
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
        errors.push(verr(
            "V-017",
            "attack.severity.confidence",
            format!("severity.confidence must be 0-100, got {}", c),
        ));
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
            let inferred = infer_execution_protocol(&doc.attack.execution);
            let protocol = ind.protocol.as_deref().or(inferred.as_deref());

            // §2.21: For indicators targeting unrecognized protocols (not in
            // the registry), skip surface validation — require explicit targets
            // instead (handled by the user, not auto-resolved by N-004).
            let is_known_protocol = protocol.is_some_and(|proto| KNOWN_PROTOCOLS.contains(&proto));
            if !is_known_protocol {
                continue;
            }

            let Some(entry) = lookup_surface(&ind.surface) else {
                errors.push(verr(
                    "V-018",
                    format!("attack.indicators[{}].surface", i),
                    format!("unknown surface: '{}'", ind.surface),
                ));
                continue;
            };
            if entry.protocol != protocol.unwrap() {
                errors.push(verr(
                    "V-018",
                    format!("attack.indicators[{}].surface", i),
                    format!(
                        "surface '{}' is for protocol '{}', but indicator targets '{}'",
                        ind.surface,
                        entry.protocol,
                        protocol.unwrap()
                    ),
                ));
            }
        }
    }
}

// ─── V-019 ──────────────────────────────────────────────────────────────────

fn v019_count_match_require_event(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(trigger) = &phase.trigger {
                if trigger.event.is_none()
                    && (trigger.count.is_some() || trigger.match_predicate.is_some())
                {
                    errors.push(verr(
                        "V-019",
                        format!("{}.phases[{}].trigger", actor_info.path_prefix, pi),
                        "trigger.count and trigger.match require event to be present",
                    ));
                }
                if let Some(count) = trigger.count
                    && count < 1
                {
                    errors.push(verr(
                        "V-019",
                        format!("{}.phases[{}].trigger.count", actor_info.path_prefix, pi),
                        format!("trigger.count must be >= 1, got {}", count),
                    ));
                }
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
                errors.push(verr(
                    "V-021",
                    format!("attack.indicators[{}].pattern.target", i),
                    format!("invalid wildcard dot-path: '{}'", target),
                ));
            }
            if let Some(semantic) = &ind.semantic
                && let Some(target) = &semantic.target
                && !is_valid_wildcard_dot_path(target)
            {
                errors.push(verr(
                    "V-021",
                    format!("attack.indicators[{}].semantic.target", i),
                    format!("invalid wildcard dot-path: '{}'", target),
                ));
            }
        }
    }
}

// Path validation functions (is_valid_wildcard_dot_path, is_valid_simple_dot_path)
// are defined in primitives.rs and imported above.

// ─── V-022 ──────────────────────────────────────────────────────────────────

fn v022_semantic_threshold(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(semantic) = &ind.semantic
                && let Some(threshold) = semantic.threshold
                && !(0.0..=1.0).contains(&threshold)
            {
                errors.push(verr(
                    "V-022",
                    format!("attack.indicators[{}].semantic.threshold", i),
                    format!(
                        "semantic threshold must be in [0.0, 1.0], got {}",
                        threshold
                    ),
                ));
            }
        }
    }
}

// ─── V-023 ──────────────────────────────────────────────────────────────────

fn v023_attack_id_format(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(id) = &doc.attack.id
        && !ATTACK_ID_RE.is_match(id)
    {
        errors.push(verr(
            "V-023",
            "attack.id",
            format!(
                "attack.id must match ^[A-Z][A-Z0-9-]*-[0-9]{{3,}}$, got '{}'",
                id
            ),
        ));
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
                    errors.push(verr(
                            "V-024",
                            format!("attack.indicators[{}].id", i),
                            format!(
                                "indicator.id must match ^[A-Z][A-Z0-9-]*-[0-9]{{3,}}-[0-9]{{2,}}$, got '{}'",
                                ind_id
                            ),
                        ));
                } else {
                    // Prefix must equal attack.id
                    // The prefix is everything before the final -NN segment
                    if let Some(last_dash) = ind_id.rfind('-') {
                        let prefix = &ind_id[..last_dash];
                        if prefix != attack_id {
                            errors.push(verr(
                                "V-024",
                                format!("attack.indicators[{}].id", i),
                                format!(
                                    "indicator.id prefix '{}' must equal attack.id '{}'",
                                    prefix, attack_id
                                ),
                            ));
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
                errors.push(verr(
                    "V-025",
                    format!("attack.indicators[{}].confidence", i),
                    format!("indicator.confidence must be 0-100, got {}", conf),
                ));
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
                        errors.push(verr(
                                "V-026",
                                format!(
                                    "attack.indicators[{}].expression.variables.{}",
                                    i, key
                                ),
                                format!(
                                    "expression variable value must be a valid simple dot-path, got '{}'",
                                    path
                                ),
                            ));
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
                        errors.push(verr(
                            "V-027",
                            format!(
                                "{}.phases[{}].trigger.match.{}",
                                actor_info.path_prefix, pi, key
                            ),
                            format!(
                                "match predicate key must be a valid simple dot-path, got '{}'",
                                key
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Check response entry `when` predicate keys in state values
    check_when_predicates_in_state(doc, errors);
}

fn check_when_predicates_in_state(doc: &Document, errors: &mut Vec<ValidationError>) {
    for_each_state_response_entry(doc, |entry, path| {
        if let Some(when_val) = entry.get("when")
            && let Some(pred_map) = when_val.as_object()
        {
            for key in pred_map.keys() {
                if !is_valid_simple_dot_path(key) {
                    errors.push(verr(
                        "V-027",
                        format!("{}.when.{}", path, key),
                        format!(
                            "match predicate key must be a valid simple dot-path, got '{}'",
                            key
                        ),
                    ));
                }
            }
        }
    });
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
                errors.push(verr(
                    "V-028",
                    format!("attack.execution.phases[{}].mode", i),
                    "phase.mode is required when execution.mode is absent",
                ));
            }
        }
    }

    // When execution.mode is absent — indicators must specify protocol
    if exec.mode.is_none()
        && let Some(indicators) = &doc.attack.indicators
    {
        for (i, ind) in indicators.iter().enumerate() {
            if ind.protocol.is_none() {
                errors.push(verr(
                    "V-028",
                    format!("attack.indicators[{}].protocol", i),
                    "indicator.protocol is required when execution.mode is absent",
                ));
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
                    errors.push(verr(
                        "V-029",
                        format!("{}.phases[{}].trigger.event", actor_info.path_prefix, pi),
                        format!(
                            "event '{}' is not valid for mode '{}'",
                            event, resolved_mode
                        ),
                    ));
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
        errors.push(verr(
            "V-030",
            "attack.execution",
            "exactly one of state, phases, or actors must be present",
        ));
    } else if count > 1 {
        errors.push(verr(
            "V-030",
            "attack.execution",
            "state, phases, and actors are mutually exclusive",
        ));
    }

    // When state is present, mode must also be present
    if has_state && exec.mode.is_none() {
        errors.push(verr(
            "V-030",
            "attack.execution.mode",
            "execution.mode is required when execution.state is present",
        ));
    }
}

// ─── V-031 ──────────────────────────────────────────────────────────────────

fn v031_multi_actor_constraints(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(actors) = &doc.attack.execution.actors {
        let mut seen_names = std::collections::HashSet::new();

        for (i, actor) in actors.iter().enumerate() {
            // Unique names
            if !seen_names.insert(&actor.name) {
                errors.push(verr(
                    "V-031",
                    format!("attack.execution.actors[{}].name", i),
                    format!("duplicate actor name: {}", actor.name),
                ));
            }

            // Name pattern
            if !SNAKE_CASE_RE.is_match(&actor.name) {
                errors.push(verr(
                    "V-031",
                    format!("attack.execution.actors[{}].name", i),
                    format!(
                        "actor name must match [a-z][a-z0-9_]*, got '{}'",
                        actor.name
                    ),
                ));
            }

            // Mode required (already enforced by struct, but check empty)
            if actor.mode.is_empty() {
                errors.push(verr(
                    "V-031",
                    format!("attack.execution.actors[{}].mode", i),
                    "actor must declare mode",
                ));
            }

            // At least one phase
            if actor.phases.is_empty() {
                errors.push(verr(
                    "V-031",
                    format!("attack.execution.actors[{}].phases", i),
                    format!("actor '{}' must have at least one phase", actor.name),
                ));
            }

            // Phase names unique within actor
            let mut phase_names = std::collections::HashSet::new();
            for (pi, phase) in actor.phases.iter().enumerate() {
                if let Some(name) = &phase.name
                    && !phase_names.insert(name.clone())
                {
                    errors.push(verr(
                        "V-031",
                        format!("attack.execution.actors[{}].phases[{}].name", i, pi),
                        format!(
                            "duplicate phase name '{}' within actor '{}'",
                            name, actor.name
                        ),
                    ));
                }
            }
        }
    }
}

// ─── V-032 ──────────────────────────────────────────────────────────────────

fn v032_cross_actor_refs(doc: &Document, errors: &mut Vec<ValidationError>) {
    let actor_names = collect_actor_names(doc);
    for_each_state(doc, |state, path| {
        check_cross_actor_refs_in_value(state, &actor_names, path, errors, 0);
    });
}

fn check_cross_actor_refs_in_value(
    value: &serde_json::Value,
    actor_names: &std::collections::HashSet<String>,
    path: &str,
    errors: &mut Vec<ValidationError>,
    depth: usize,
) {
    if depth > MAX_VALUE_DEPTH {
        return;
    }
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
                    depth + 1,
                );
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                // "responses" array is reported as singular "response" per spec
                if k == "responses" {
                    if let Some(arr) = v.as_array() {
                        let child_path = format!("{}.response", path);
                        for item in arr {
                            check_cross_actor_refs_in_value(
                                item,
                                actor_names,
                                &child_path,
                                errors,
                                depth + 1,
                            );
                        }
                    }
                } else {
                    check_cross_actor_refs_in_value(
                        v,
                        actor_names,
                        &format!("{}.{}", path, k),
                        errors,
                        depth + 1,
                    );
                }
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
            errors.push(verr(
                "V-032",
                path.to_string(),
                format!(
                    "cross-actor reference '{{{{{}}}}}' targets unknown actor '{}'",
                    &cap[0].trim_start_matches("{{").trim_end_matches("}}"),
                    actor_name
                ),
            ));
        }
    }
}

// ─── V-033 ──────────────────────────────────────────────────────────────────

fn v033_content_synthesize_exclusivity(doc: &Document, errors: &mut Vec<ValidationError>) {
    for_each_state(doc, |state, path| {
        check_response_exclusivity(state, path, errors);
    });
}

fn check_response_exclusivity(
    state: &serde_json::Value,
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
                        errors.push(verr(
                            "V-033",
                            format!("{}.tools[{}].response", path, ti),
                            "content and synthesize are mutually exclusive",
                        ));
                    }
                }
                // Plural "responses" form — path uses singular "response" per spec
                if let Some(responses) = tool.get("responses").and_then(|v| v.as_array()) {
                    for resp in responses {
                        let has_content = resp.get("content").is_some();
                        let has_synthesize = resp.get("synthesize").is_some();
                        if has_content && has_synthesize {
                            errors.push(verr(
                                "V-033",
                                format!("{}.tools[{}].response", path, ti),
                                "content and synthesize are mutually exclusive",
                            ));
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
                            errors.push(verr(
                                "V-033",
                                format!("{}.prompts[{}].responses[{}]", path, pi, ri),
                                "messages and synthesize are mutually exclusive",
                            ));
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
                let has_history = resp.get("history").is_some();
                let has_synthesize = resp.get("synthesize").is_some();
                if (has_messages || has_artifacts || has_history) && has_synthesize {
                    errors.push(verr(
                        "V-033",
                        format!("{}.task_responses[{}]", path, ri),
                        "messages/artifacts and synthesize are mutually exclusive",
                    ));
                }
            }
        }

        // MCP sampling_responses
        if let Some(sampling) = obj.get("sampling_responses").and_then(|v| v.as_array()) {
            for (ri, resp) in sampling.iter().enumerate() {
                let has_content = resp.get("content").is_some();
                let has_synthesize = resp.get("synthesize").is_some();
                if has_content && has_synthesize {
                    errors.push(verr(
                        "V-033",
                        format!("{}.sampling_responses[{}]", path, ri),
                        "content and synthesize are mutually exclusive",
                    ));
                }
            }
        }

        // MCP elicitation_responses
        if let Some(elicitation) = obj.get("elicitation_responses").and_then(|v| v.as_array()) {
            for (ri, resp) in elicitation.iter().enumerate() {
                let has_content = resp.get("content").is_some();
                let has_synthesize = resp.get("synthesize").is_some();
                if has_content && has_synthesize {
                    errors.push(verr(
                        "V-033",
                        format!("{}.elicitation_responses[{}]", path, ri),
                        "content and synthesize are mutually exclusive",
                    ));
                }
            }
        }

        // AG-UI run_agent_input
        if let Some(rai) = obj.get("run_agent_input") {
            let has_messages = rai.get("messages").is_some();
            let has_synthesize = rai.get("synthesize").is_some();
            if has_messages && has_synthesize {
                errors.push(verr(
                    "V-033",
                    format!("{}.run_agent_input", path),
                    "messages and synthesize are mutually exclusive",
                ));
            }
        }
    }
}

// ─── V-034 ──────────────────────────────────────────────────────────────────

fn v034_catch_all_constraints(doc: &Document, errors: &mut Vec<ValidationError>) {
    for_each_state(doc, |state, path| {
        check_catch_all_in_state(state, path, errors);
    });
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

        // MCP sampling_responses
        if let Some(sampling) = obj.get("sampling_responses").and_then(|v| v.as_array()) {
            check_catch_all_list(sampling, &format!("{}.sampling_responses", path), errors);
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
        errors.push(verr(
            "V-034",
            path.to_string(),
            format!(
                "at most one entry may omit 'when' (catch-all), found {}",
                catch_all_count
            ),
        ));
    }
}

// ─── V-035 ──────────────────────────────────────────────────────────────────

fn v035_synthesize_prompt(doc: &Document, errors: &mut Vec<ValidationError>) {
    for_each_state(doc, |state, path| {
        check_synthesize_prompts(state, path, errors, 0);
    });
}

fn check_synthesize_prompts(
    value: &serde_json::Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    depth: usize,
) {
    if depth > MAX_VALUE_DEPTH {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            if let Some(synth) = map.get("synthesize")
                && let Some(synth_obj) = synth.as_object()
            {
                match synth_obj.get("prompt") {
                    Some(serde_json::Value::String(s)) if s.is_empty() => {
                        errors.push(verr(
                            "V-035",
                            format!("{}.synthesize.prompt", path),
                            "synthesize.prompt must be non-empty",
                        ));
                    }
                    None => {
                        errors.push(verr(
                            "V-035",
                            format!("{}.synthesize.prompt", path),
                            "synthesize.prompt must be present",
                        ));
                    }
                    _ => {}
                }
            }
            for (k, v) in map {
                if k != "synthesize" {
                    check_synthesize_prompts(v, &format!("{}.{}", path, k), errors, depth + 1);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                check_synthesize_prompts(v, &format!("{}[{}]", path, i), errors, depth + 1);
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
    // Check execution.mode pattern (V-036)
    if let Some(mode) = &doc.attack.execution.mode
        && !MODE_RE.is_match(mode)
    {
        errors.push(verr(
            "V-036",
            "attack.execution.mode",
            format!(
                "mode must match [a-z][a-z0-9_]*_(server|client), got '{}'",
                mode
            ),
        ));
    }
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
                errors.push(verr(
                    "V-036",
                    format!("attack.execution.actors[{}].mode", i),
                    format!(
                        "mode must match [a-z][a-z0-9_]*_(server|client), got '{}'",
                        actor.mode
                    ),
                ));
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
                errors.push(verr(
                    "V-036",
                    format!("{}.phases[{}].mode", actor_info.path_prefix, pi),
                    format!(
                        "mode must match [a-z][a-z0-9_]*_(server|client), got '{}'",
                        mode
                    ),
                ));
            }
        }
    }

    // Check indicator protocols
    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            if let Some(protocol) = &ind.protocol {
                if !PROTOCOL_RE.is_match(protocol) {
                    errors.push(verr(
                        "V-036",
                        format!("attack.indicators[{}].protocol", i),
                        format!("protocol must match [a-z][a-z0-9_]*, got '{}'", protocol),
                    ));
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
        errors.push(verr(
            "V-037",
            "attack.version",
            format!(
                "attack.version must be a positive integer (>= 1), got {}",
                version
            ),
        ));
    }
}

// ─── V-038 ──────────────────────────────────────────────────────────────────

fn v038_trigger_after_duration(doc: &Document, errors: &mut Vec<ValidationError>) {
    // Validate trigger.after durations by actually parsing them
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(trigger) = &phase.trigger
                && let Some(after) = &trigger.after
                && let Err(e) = crate::primitives::parse_duration(after)
            {
                errors.push(verr(
                    "V-038",
                    format!("{}.phases[{}].trigger.after", actor_info.path_prefix, pi),
                    format!("invalid duration '{}': {}", after, e),
                ));
            }
        }
    }
}

// ─── V-039 ──────────────────────────────────────────────────────────────────

fn v039_extractor_name_pattern(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(extractors) = &phase.extractors {
                for (ei, ext) in extractors.iter().enumerate() {
                    if !SNAKE_CASE_RE.is_match(&ext.name) {
                        errors.push(verr(
                            "V-039",
                            format!(
                                "{}.phases[{}].extractors[{}].name",
                                actor_info.path_prefix, pi, ei
                            ),
                            format!(
                                "extractor name must match [a-z][a-z0-9_]*, got '{}'",
                                ext.name
                            ),
                        ));
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
                errors.push(verr(
                    "V-040",
                    format!("{}.phases[{}].extractors", actor_info.path_prefix, pi),
                    "extractors, when present, must contain at least one entry",
                ));
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
                        errors.push(verr(
                            "V-041",
                            format!("attack.indicators[{}].expression.variables.{}", i, key),
                            format!(
                                "expression variable key must be a valid CEL identifier, got '{}'",
                                key
                            ),
                        ));
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
                errors.push(verr(
                    "V-042",
                    format!("{}.phases[{}].trigger", actor_info.path_prefix, pi),
                    "trigger must specify at least one of event or after",
                ));
            }
        }
    }
}

// ─── V-043 ──────────────────────────────────────────────────────────────────

// V-043 is now enforced at parse time in Action::deserialize.

// ─── V-044 ──────────────────────────────────────────────────────────────────

fn v044_regex_extractor_capture_group(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(extractors) = &phase.extractors {
                for (ei, ext) in extractors.iter().enumerate() {
                    if ext.extractor_type == crate::enums::ExtractorType::Regex {
                        // Check that the selector contains at least one capture group
                        if !has_capture_group(&ext.selector) {
                            errors.push(verr(
                                "V-044",
                                format!(
                                    "{}.phases[{}].extractors[{}].selector",
                                    actor_info.path_prefix, pi, ei
                                ),
                                "regex extractor selector must contain at least one capture group",
                            ));
                        }
                    }
                }
            }
        }
    }
}

/// Check if a regex pattern contains at least one unescaped capture group.
fn has_capture_group(pattern: &str) -> bool {
    compile_user_regex(pattern)
        .map(|re| re.captures_len() > 1)
        .unwrap_or(false)
}

// ─── V-045 ──────────────────────────────────────────────────────────────────

fn v045_on_enter_non_empty(doc: &Document, errors: &mut Vec<ValidationError>) {
    for actor_info in collect_actors(doc) {
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(actions) = &phase.on_enter
                && actions.is_empty()
            {
                errors.push(verr(
                    "V-045",
                    format!("{}.phases[{}].on_enter", actor_info.path_prefix, pi),
                    "on_enter, when present, must contain at least one action",
                ));
            }
        }
    }
}

// ─── V-046 ──────────────────────────────────────────────────────────────────

fn v046_phase_mode_matches_actor(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(actors) = &doc.attack.execution.actors {
        for (ai, actor) in actors.iter().enumerate() {
            for (pi, phase) in actor.phases.iter().enumerate() {
                if let Some(pm) = &phase.mode
                    && *pm != actor.mode
                {
                    errors.push(verr(
                        "V-046",
                        format!("attack.execution.actors[{}].phases[{}].mode", ai, pi),
                        format!("phase mode '{}' must match actor mode '{}'", pm, actor.mode),
                    ));
                }
            }
        }
    }
}

// ─── V-047 ──────────────────────────────────────────────────────────────────

fn v047_a2a_client_mutual_exclusivity(doc: &Document, errors: &mut Vec<ValidationError>) {
    let a2a_client_keys = [
        "task_message",
        "task_query",
        "task_cancel",
        "task_resubscribe",
        "push_notification_config",
        "get_authenticated_extended_card",
    ];

    let mut check_state = |state: &Value, path: &str| {
        let Some(obj) = state.as_object() else {
            return;
        };
        let present: Vec<&str> = a2a_client_keys
            .iter()
            .copied()
            .filter(|k| obj.contains_key(*k))
            .collect();
        if present.len() > 1 {
            errors.push(verr(
                "V-047",
                path,
                format!(
                    "a2a_client state must contain at most one action key, found: {}",
                    present.join(", ")
                ),
            ));
        }
        // Check task_message sub-exclusivity: message vs synthesize
        if let Some(tm) = obj.get("task_message").and_then(|v| v.as_object())
            && tm.contains_key("message")
            && tm.contains_key("synthesize")
        {
            errors.push(verr(
                "V-047",
                format!("{}.task_message", path),
                "task_message: message and synthesize are mutually exclusive",
            ));
        }
    };

    // Single-state form: use execution.mode
    if let Some(state) = &doc.attack.execution.state {
        let mode = doc.attack.execution.mode.as_deref().unwrap_or("");
        if mode == "a2a_client" {
            check_state(state, "attack.execution.state");
        }
    }

    // Multi-actor/multi-phase forms
    for actor_info in collect_actors(doc) {
        if actor_info.mode != Some("a2a_client") {
            continue;
        }
        for (pi, phase) in actor_info.phases.iter().enumerate() {
            if let Some(state) = &phase.state {
                check_state(
                    state,
                    &format!("{}.phases[{}].state", actor_info.path_prefix, pi),
                );
            }
        }
    }
}

// ─── V-048 ──────────────────────────────────────────────────────────────────

fn v048_impact_no_duplicates(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(impact) = &doc.attack.impact {
        let mut seen = std::collections::HashSet::new();
        for item in impact {
            if !seen.insert(item) {
                errors.push(verr(
                    "V-048",
                    "attack.impact",
                    "impact must not contain duplicate values",
                ));
                break;
            }
        }
    }
}

// ─── V-049 ──────────────────────────────────────────────────────────────────

fn v049_grace_period_duration(doc: &Document, errors: &mut Vec<ValidationError>) {
    if let Some(gp) = &doc.attack.grace_period
        && let Err(e) = crate::primitives::parse_duration(gp)
    {
        errors.push(verr(
            "V-049",
            "attack.grace_period",
            format!("invalid duration '{}': {}", gp, e),
        ));
    }
}

// ─── V-050 ──────────────────────────────────────────────────────────────────

fn v050_correlation_requires_indicators(doc: &Document, errors: &mut Vec<ValidationError>) {
    if doc.attack.correlation.is_some() && doc.attack.indicators.is_none() {
        errors.push(verr(
            "V-050",
            "attack.correlation",
            "correlation requires indicators to be present",
        ));
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
    let actor_names = collect_actor_names(doc);

    // Single-phase form has no phase-local extractor declarations.
    if let Some(state) = &doc.attack.execution.state {
        let declared = std::collections::HashSet::new();
        if check_undeclared_refs_in_value(state, &declared, &actor_names, 0) {
            warnings.push(Diagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "W-004".to_string(),
                path: None,
                message: "template references undeclared extractor".to_string(),
            });
            return; // Emit once per document
        }
    }

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
                has_undeclared |= check_undeclared_refs_in_value(state, &declared, &actor_names, 0);
            }

            // Check on_enter actions for template references
            if let Some(actions) = &phase.on_enter {
                for action in actions {
                    let action_value = serde_json::to_value(action).unwrap_or_default();
                    has_undeclared |=
                        check_undeclared_refs_in_value(&action_value, &declared, &actor_names, 0);
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
    depth: usize,
) -> bool {
    if depth > MAX_VALUE_DEPTH {
        return false;
    }
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
            .any(|v| check_undeclared_refs_in_value(v, declared, actor_names, depth + 1)),
        serde_json::Value::Object(map) => map
            .values()
            .any(|v| check_undeclared_refs_in_value(v, declared, actor_names, depth + 1)),
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
