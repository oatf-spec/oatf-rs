//! OATF document types per the format specification §2.
//!
//! All struct fields follow the specification naming. Extension fields (`x-*` prefixed)
//! are captured via `#[serde(flatten)] HashMap<String, Value>` on types that support them.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;

use crate::enums::*;

// ─── §2.2 Document ──────────────────────────────────────────────────────────

/// The top-level container for a parsed OATF document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Document {
    /// OATF format version string (e.g., `"0.1"`).
    pub oatf: String,
    /// Optional JSON Schema URI for editor validation.
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// The attack description and all contained structures.
    pub attack: Attack,
    /// Whether `oatf` was the first key in the original YAML (for W-001).
    #[serde(skip)]
    pub oatf_is_first_key: bool,
}

// ─── §2.3 Attack ─────────────────────────────────────────────────────────────

/// The attack envelope containing metadata, execution, and indicators.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attack {
    /// Unique attack identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Human-readable attack name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Document version number (integer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// Document lifecycle status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// ISO 8601 creation date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// ISO 8601 last-modified date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    /// Author name or identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Human-readable attack description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Grace period duration string (e.g., `"30d"`) for responsible disclosure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<String>,
    /// Attack severity (scalar string or object with level + confidence).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Categories of harm caused by this attack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<Vec<Impact>>,
    /// OATF taxonomy classification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    /// External references (URLs, papers, advisories).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<Reference>>,
    /// Execution plan describing the attack phases and actors.
    pub execution: Execution,
    /// Detection indicators for this attack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicators: Option<Vec<Indicator>>,
    /// Verdict correlation configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation: Option<Correlation>,
    /// Extension fields (`x-*` prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.3a Correlation ───────────────────────────────────────────────────────

/// Configuration for how indicator verdicts combine into an attack-level result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Correlation {
    /// Correlation logic (`any` or `all`). Defaults to `any` at evaluation time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logic: Option<CorrelationLogic>,
}

// ─── §2.4 Severity ───────────────────────────────────────────────────────────

/// Severity can be either a scalar string or an object form.
/// During deserialization, a bare string like "high" is accepted.
/// After normalization, always in object form.
#[derive(Clone, Debug)]
pub enum Severity {
    /// Shorthand scalar form (e.g., `"high"`). Normalized to `Object` by N-003.
    Scalar(SeverityLevel),
    /// Full object form with level and optional confidence.
    Object {
        /// Severity level classification.
        level: SeverityLevel,
        /// Confidence percentage (0–100), if specified.
        confidence: Option<i64>,
    },
}

impl Serialize for Severity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Severity::Scalar(level) => level.serialize(serializer),
            Severity::Object { level, confidence } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("level", level)?;
                if let Some(c) = confidence {
                    map.serialize_entry("confidence", c)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match &value {
            Value::String(s) => {
                let level: SeverityLevel = serde_json::from_value(Value::String(s.clone()))
                    .map_err(serde::de::Error::custom)?;
                Ok(Severity::Scalar(level))
            }
            Value::Object(map) => {
                let level_val = map.get("level").ok_or_else(|| {
                    serde::de::Error::custom("severity object must have 'level' field")
                })?;
                let level: SeverityLevel =
                    serde_json::from_value(level_val.clone()).map_err(serde::de::Error::custom)?;
                let confidence = match map.get("confidence") {
                    Some(v) if v.is_null() => None,
                    Some(v) => Some(v.as_i64().ok_or_else(|| {
                        serde::de::Error::custom(format!(
                            "severity.confidence must be an integer, got {}",
                            v
                        ))
                    })?),
                    None => None,
                };
                Ok(Severity::Object { level, confidence })
            }
            _ => Err(serde::de::Error::custom(
                "severity must be a string or object",
            )),
        }
    }
}

// ─── §2.5 Classification ────────────────────────────────────────────────────

/// OATF taxonomy classification with optional framework mappings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Classification {
    /// OATF taxonomy category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,
    /// Mappings to external security frameworks (MITRE ATT&CK, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Vec<FrameworkMapping>>,
    /// Free-form tags for categorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

// ─── §2.6 Execution ─────────────────────────────────────────────────────────

/// Execution plan describing how the attack is carried out.
///
/// Exactly one of `state`, `phases`, or `actors` must be present (three
/// mutually exclusive execution forms). After normalization, only `actors` is set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execution {
    /// Protocol mode for single-phase form (e.g., `"mcp/sse"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Single-phase execution state (JSON object). Mutually exclusive with `phases`/`actors`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    /// Multi-phase execution form. Mutually exclusive with `state`/`actors`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phases: Option<Vec<Phase>>,
    /// Multi-actor execution form (canonical). Mutually exclusive with `state`/`phases`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<Actor>>,
    /// Extension fields (`x-*` prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.6a Actor ─────────────────────────────────────────────────────────────

/// An actor in the multi-actor execution form, representing a protocol participant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Actor {
    /// Actor name identifier (e.g., `"attacker"`, `"victim"`).
    pub name: String,
    /// Protocol mode (e.g., `"mcp/sse"`, `"a2a"`).
    pub mode: String,
    /// Ordered list of execution phases for this actor.
    pub phases: Vec<Phase>,
    /// Extension fields (`x-*` prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.7 Phase ──────────────────────────────────────────────────────────────

/// An execution phase within an actor's plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase {
    /// Phase name identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable phase description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Protocol mode override for this phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Phase execution state (JSON object describing protocol messages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    /// Data extractors applied to protocol messages during this phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extractors: Option<Vec<Extractor>>,
    /// Actions executed when this phase begins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_enter: Option<Vec<Action>>,
    /// Trigger condition that advances to the next phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Trigger>,
    /// Extension fields (`x-*` prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.7a Action ────────────────────────────────────────────────────────────

/// An entry action executed when a phase begins.
/// Tagged union with known variants + catch-all for binding-specific actions.
#[derive(Clone, Debug)]
pub enum Action {
    /// Send a protocol notification message.
    SendNotification {
        /// Notification method name.
        method: String,
        /// Optional notification parameters.
        params: Option<Value>,
        /// Extension fields (`x-*` prefixed).
        extensions: HashMap<String, Value>,
        /// Number of non-extension keys in the original object (for V-043).
        non_ext_key_count: usize,
    },
    /// Emit a log message.
    Log {
        /// Log message text.
        message: String,
        /// Log level (defaults to `info`).
        level: Option<LogLevel>,
        /// Extension fields (`x-*` prefixed).
        extensions: HashMap<String, Value>,
        /// Number of non-extension keys in the original object (for V-043).
        non_ext_key_count: usize,
    },
    /// Send a user elicitation request.
    SendElicitation {
        /// Elicitation message text.
        message: String,
        /// Elicitation mode (`form` or `url`).
        mode: Option<ElicitationMode>,
        /// JSON Schema for form-mode elicitation.
        #[allow(non_snake_case)]
        requested_schema: Option<Value>,
        /// URL for url-mode elicitation.
        url: Option<String>,
        /// Extension fields (`x-*` prefixed).
        extensions: HashMap<String, Value>,
        /// Number of non-extension keys in the original object (for V-043).
        non_ext_key_count: usize,
    },
    /// Binding-specific action with a single unknown key.
    BindingSpecific {
        /// The action key name.
        key: String,
        /// The action value.
        value: Value,
        /// Extension fields (`x-*` prefixed).
        extensions: HashMap<String, Value>,
        /// Number of non-extension keys in the original object (for V-043).
        non_ext_key_count: usize,
    },
}

impl Serialize for Action {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Action::SendNotification {
                method,
                params,
                extensions,
                ..
            } => {
                let mut outer = serializer.serialize_map(None)?;
                let mut inner = serde_json::Map::new();
                inner.insert("method".to_string(), Value::String(method.clone()));
                if let Some(p) = params {
                    inner.insert("params".to_string(), p.clone());
                }
                outer.serialize_entry("send_notification", &Value::Object(inner))?;
                for (k, v) in extensions {
                    outer.serialize_entry(k, v)?;
                }
                outer.end()
            }
            Action::Log {
                message,
                level,
                extensions,
                ..
            } => {
                let mut outer = serializer.serialize_map(None)?;
                let mut inner = serde_json::Map::new();
                inner.insert("message".to_string(), Value::String(message.clone()));
                if let Some(l) = level {
                    inner.insert(
                        "level".to_string(),
                        serde_json::to_value(l).unwrap_or(Value::Null),
                    );
                }
                outer.serialize_entry("log", &Value::Object(inner))?;
                for (k, v) in extensions {
                    outer.serialize_entry(k, v)?;
                }
                outer.end()
            }
            Action::SendElicitation {
                message,
                mode,
                requested_schema,
                url,
                extensions,
                ..
            } => {
                let mut outer = serializer.serialize_map(None)?;
                let mut inner = serde_json::Map::new();
                inner.insert("message".to_string(), Value::String(message.clone()));
                if let Some(m) = mode {
                    inner.insert(
                        "mode".to_string(),
                        serde_json::to_value(m).unwrap_or(Value::Null),
                    );
                }
                if let Some(rs) = requested_schema {
                    inner.insert("requestedSchema".to_string(), rs.clone());
                }
                if let Some(u) = url {
                    inner.insert("url".to_string(), Value::String(u.clone()));
                }
                outer.serialize_entry("send_elicitation", &Value::Object(inner))?;
                for (k, v) in extensions {
                    outer.serialize_entry(k, v)?;
                }
                outer.end()
            }
            Action::BindingSpecific {
                key,
                value,
                extensions,
                ..
            } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(key, value)?;
                for (k, v) in extensions {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map: serde_json::Map<String, Value> = serde_json::Map::deserialize(deserializer)?;

        let mut extensions = HashMap::new();
        let mut action_key = None;
        let mut action_value = None;
        let mut non_ext_key_count = 0usize;

        for (k, v) in &map {
            if k.starts_with("x-") {
                extensions.insert(k.clone(), v.clone());
            } else {
                non_ext_key_count += 1;
                if action_key.is_none() {
                    action_key = Some(k.clone());
                    action_value = Some(v.clone());
                }
            }
        }

        let key = action_key
            .ok_or_else(|| serde::de::Error::custom("action object must have at least one key"))?;
        let value = action_value.unwrap();

        match key.as_str() {
            "send_notification" => {
                let obj = value.as_object().ok_or_else(|| {
                    serde::de::Error::custom("send_notification must be an object")
                })?;
                let method = obj
                    .get("method")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("send_notification requires 'method'"))?
                    .to_string();
                let params = obj.get("params").cloned();
                Ok(Action::SendNotification {
                    method,
                    params,
                    extensions,
                    non_ext_key_count,
                })
            }
            "log" => {
                let obj = value
                    .as_object()
                    .ok_or_else(|| serde::de::Error::custom("log must be an object"))?;
                let message = obj
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("log requires 'message'"))?
                    .to_string();
                let level = obj
                    .get("level")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(serde::de::Error::custom)?;
                Ok(Action::Log {
                    message,
                    level,
                    extensions,
                    non_ext_key_count,
                })
            }
            "send_elicitation" => {
                let obj = value.as_object().ok_or_else(|| {
                    serde::de::Error::custom("send_elicitation must be an object")
                })?;
                let message = obj
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("send_elicitation requires 'message'"))?
                    .to_string();
                let mode = obj
                    .get("mode")
                    .map(|v| serde_json::from_value(v.clone()))
                    .transpose()
                    .map_err(serde::de::Error::custom)?;
                let requested_schema = obj.get("requestedSchema").cloned();
                let url = obj
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Ok(Action::SendElicitation {
                    message,
                    mode,
                    requested_schema,
                    url,
                    extensions,
                    non_ext_key_count,
                })
            }
            _ => Ok(Action::BindingSpecific {
                key,
                value,
                extensions,
                non_ext_key_count,
            }),
        }
    }
}

// ─── §2.8 Trigger ────────────────────────────────────────────────────────────

/// Condition that advances execution to the next phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trigger {
    /// Protocol event name (e.g., `"mcp:tool_call"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// Number of matching events required before advancing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    /// Predicate that the event payload must satisfy.
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_predicate: Option<MatchPredicate>,
    /// Duration string (e.g., `"5s"`) after which the trigger times out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

// ─── §2.8a ProtocolEvent ─────────────────────────────────────────────────────

/// A protocol event observed during execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolEvent {
    /// Qualified event type (e.g., `"mcp:tool_call"`).
    pub event_type: String,
    /// Optional event qualifier (e.g., method name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    /// Event payload content.
    pub content: Value,
}

// ─── §2.8b TriggerResult ────────────────────────────────────────────────────

/// Result of evaluating a trigger against an event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriggerResult {
    /// The trigger condition was met and execution should advance.
    Advanced {
        /// Why the trigger advanced.
        reason: AdvanceReason,
    },
    /// The trigger condition was not met.
    NotAdvanced,
}

// ─── §2.9 Extractor ─────────────────────────────────────────────────────────

/// A data extractor that captures values from protocol messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Extractor {
    /// Variable name to bind the extracted value to.
    pub name: String,
    /// Whether to extract from request or response.
    pub source: ExtractorSource,
    /// Extraction method (JSONPath or regex).
    #[serde(rename = "type")]
    pub extractor_type: ExtractorType,
    /// JSONPath expression or regex pattern.
    pub selector: String,
}

// ─── §2.10 MatchPredicate ───────────────────────────────────────────────────

/// A match predicate is a map from dot-path field references to conditions.
pub type MatchPredicate = HashMap<String, MatchEntry>;

/// Either a scalar Value (equality check) or a MatchCondition object.
#[derive(Clone, Debug)]
pub enum MatchEntry {
    /// Direct value equality comparison.
    Scalar(Value),
    /// Operator-based condition (contains, regex, etc.).
    Condition(MatchCondition),
}

impl Serialize for MatchEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            MatchEntry::Scalar(v) => v.serialize(serializer),
            MatchEntry::Condition(c) => c.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for MatchEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match &value {
            Value::Object(map) => {
                // Check if it looks like a MatchCondition (has operator keys)
                let operator_keys = [
                    "contains",
                    "starts_with",
                    "ends_with",
                    "regex",
                    "any_of",
                    "gt",
                    "lt",
                    "gte",
                    "lte",
                    "exists",
                ];
                if map.keys().any(|k| operator_keys.contains(&k.as_str())) {
                    let cond: MatchCondition =
                        serde_json::from_value(value).map_err(serde::de::Error::custom)?;
                    Ok(MatchEntry::Condition(cond))
                } else {
                    Ok(MatchEntry::Scalar(value))
                }
            }
            _ => Ok(MatchEntry::Scalar(value)),
        }
    }
}

// ─── §2.11 MatchCondition ───────────────────────────────────────────────────

/// Operator-based match condition for field comparison.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchCondition {
    /// String containment check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// String prefix check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starts_with: Option<String>,
    /// String suffix check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ends_with: Option<String>,
    /// Regular expression match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Value must be one of the given values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_of: Option<Vec<Value>>,
    /// Greater-than numeric comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gt: Option<f64>,
    /// Less-than numeric comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lt: Option<f64>,
    /// Greater-than-or-equal numeric comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gte: Option<f64>,
    /// Less-than-or-equal numeric comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lte: Option<f64>,
    /// Field existence check.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exists: Option<bool>,
}

// ─── §2.12 Indicator ────────────────────────────────────────────────────────

/// A detection indicator that matches against protocol messages.
///
/// Exactly one of `pattern`, `expression`, or `semantic` should be present.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Indicator {
    /// Unique indicator identifier (used in verdict reporting).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Protocol this indicator applies to (e.g., `"mcp"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Attack surface name (e.g., `"mcp:tool_call"`).
    pub surface: String,
    /// Human-readable indicator description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Pattern-based detection (target + condition matching).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<PatternMatch>,
    /// CEL expression-based detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<ExpressionMatch>,
    /// Semantic/intent-based detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticMatch>,
    /// Confidence percentage (0–100) for this indicator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<i64>,
    /// Indicator-level severity override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<SeverityLevel>,
    /// Known false-positive descriptions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub false_positives: Option<Vec<String>>,
    /// Extension fields (`x-*` prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.13 PatternMatch ─────────────────────────────────────────────────────

/// A pattern match indicator. Supports standard and shorthand form.
/// In standard form: has `target` and `condition`.
/// In shorthand form: has operator keys directly (e.g., `contains`, `regex`).
#[derive(Clone, Debug)]
pub struct PatternMatch {
    /// JSONPath target to match against.
    pub target: Option<String>,
    /// Condition to evaluate against the resolved target value.
    pub condition: Option<Condition>,
    // Shorthand operator fields (before normalization)
    /// Shorthand: string containment check.
    pub contains: Option<String>,
    /// Shorthand: string prefix check.
    pub starts_with: Option<String>,
    /// Shorthand: string suffix check.
    pub ends_with: Option<String>,
    /// Shorthand: regular expression match.
    pub regex: Option<String>,
    /// Shorthand: value must be one of the given values.
    pub any_of: Option<Vec<Value>>,
    /// Shorthand: greater-than numeric comparison.
    pub gt: Option<f64>,
    /// Shorthand: less-than numeric comparison.
    pub lt: Option<f64>,
    /// Shorthand: greater-than-or-equal numeric comparison.
    pub gte: Option<f64>,
    /// Shorthand: less-than-or-equal numeric comparison.
    pub lte: Option<f64>,
}

impl PatternMatch {
    /// Returns true if this pattern is in shorthand form (has direct operator keys).
    pub fn is_shorthand(&self) -> bool {
        self.condition.is_none() && self.is_shorthand_fields_present()
    }

    /// Returns true if any shorthand operator field is present.
    pub fn is_shorthand_fields_present(&self) -> bool {
        self.contains.is_some()
            || self.starts_with.is_some()
            || self.ends_with.is_some()
            || self.regex.is_some()
            || self.any_of.is_some()
            || self.gt.is_some()
            || self.lt.is_some()
            || self.gte.is_some()
            || self.lte.is_some()
    }
}

impl Serialize for PatternMatch {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        if let Some(ref t) = self.target {
            map.serialize_entry("target", t)?;
        }
        if let Some(ref c) = self.condition {
            map.serialize_entry("condition", c)?;
        }
        // Shorthand fields (only present before normalization)
        if let Some(ref v) = self.contains {
            map.serialize_entry("contains", v)?;
        }
        if let Some(ref v) = self.starts_with {
            map.serialize_entry("starts_with", v)?;
        }
        if let Some(ref v) = self.ends_with {
            map.serialize_entry("ends_with", v)?;
        }
        if let Some(ref v) = self.regex {
            map.serialize_entry("regex", v)?;
        }
        if let Some(ref v) = self.any_of {
            map.serialize_entry("any_of", v)?;
        }
        if let Some(v) = self.gt {
            map.serialize_entry("gt", &v)?;
        }
        if let Some(v) = self.lt {
            map.serialize_entry("lt", &v)?;
        }
        if let Some(v) = self.gte {
            map.serialize_entry("gte", &v)?;
        }
        if let Some(v) = self.lte {
            map.serialize_entry("lte", &v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for PatternMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let map = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("pattern must be an object"))?;

        let target = map
            .get("target")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let condition = map.get("condition").map(|v| {
            // Condition can be a bare value or a MatchCondition object
            Condition::from_value(v.clone())
        });

        // Shorthand operator fields
        let contains = map
            .get("contains")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let starts_with = map
            .get("starts_with")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let ends_with = map
            .get("ends_with")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let regex = map
            .get("regex")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let any_of = map.get("any_of").and_then(|v| v.as_array()).cloned();
        let gt = map.get("gt").and_then(|v| v.as_f64());
        let lt = map.get("lt").and_then(|v| v.as_f64());
        let gte = map.get("gte").and_then(|v| v.as_f64());
        let lte = map.get("lte").and_then(|v| v.as_f64());

        Ok(PatternMatch {
            target,
            condition,
            contains,
            starts_with,
            ends_with,
            regex,
            any_of,
            gt,
            lt,
            gte,
            lte,
        })
    }
}

/// A Condition is either a bare Value (equality) or a MatchCondition object.
#[derive(Clone, Debug)]
pub enum Condition {
    /// Direct value equality comparison.
    Equality(Value),
    /// Operator-based condition.
    Operators(MatchCondition),
}

impl Condition {
    pub fn from_value(v: Value) -> Self {
        match &v {
            Value::Object(map) => {
                let operator_keys = [
                    "contains",
                    "starts_with",
                    "ends_with",
                    "regex",
                    "any_of",
                    "gt",
                    "lt",
                    "gte",
                    "lte",
                    "exists",
                ];
                if map.keys().any(|k| operator_keys.contains(&k.as_str()))
                    && let Ok(cond) = serde_json::from_value::<MatchCondition>(v.clone())
                {
                    return Condition::Operators(cond);
                }
                Condition::Equality(v)
            }
            _ => Condition::Equality(v),
        }
    }
}

impl Serialize for Condition {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Condition::Equality(v) => v.serialize(serializer),
            Condition::Operators(c) => c.serialize(serializer),
        }
    }
}

// ─── §2.14 ExpressionMatch ──────────────────────────────────────────────────

/// A CEL expression-based detection indicator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpressionMatch {
    /// CEL expression to evaluate.
    pub cel: String,
    /// Variable bindings: name → JSONPath.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<HashMap<String, String>>,
}

// ─── §2.15 SemanticMatch ────────────────────────────────────────────────────

/// A semantic/intent-based detection indicator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticMatch {
    /// JSONPath target to extract text from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Natural-language intent description to match against.
    pub intent: String,
    /// Classification hint for the semantic evaluator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_class: Option<SemanticIntentClass>,
    /// Similarity threshold (0.0–1.0); defaults to 0.7.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    /// Positive and negative examples for few-shot guidance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<SemanticExamples>,
}

// ─── §2.16 SemanticExamples ─────────────────────────────────────────────────

/// Positive and negative examples for semantic matching guidance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticExamples {
    /// Examples that should match the intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub positive: Option<Vec<String>>,
    /// Examples that should not match the intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negative: Option<Vec<String>>,
}

// ─── §2.17 Reference ────────────────────────────────────────────────────────

/// An external reference (URL, paper, advisory).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reference {
    /// Reference URL.
    pub url: String,
    /// Human-readable title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ─── §2.18 FrameworkMapping ─────────────────────────────────────────────────

/// A mapping to an external security framework (e.g., MITRE ATT&CK).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameworkMapping {
    /// Framework name (e.g., `"MITRE ATT&CK"`).
    pub framework: String,
    /// Framework-specific identifier (e.g., `"T1059"`).
    pub id: String,
    /// Human-readable technique/entry name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// URL to the framework entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Relationship type (primary or related).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<Relationship>,
}

// ─── §2.19 Verdict Types ────────────────────────────────────────────────────

/// Result of evaluating a single indicator against a protocol message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndicatorVerdict {
    /// Identifier of the evaluated indicator.
    pub indicator_id: String,
    /// Evaluation result.
    pub result: IndicatorResult,
    /// ISO 8601 timestamp of the evaluation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Supporting evidence (e.g., matched value, error message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Source that produced this verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Attack-level verdict computed from indicator verdicts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttackVerdict {
    /// Identifier of the evaluated attack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_id: Option<String>,
    /// Overall attack result.
    pub result: AttackResult,
    /// Individual indicator verdicts.
    pub indicator_verdicts: Vec<IndicatorVerdict>,
    /// Summary counts of indicator results.
    pub evaluation_summary: EvaluationSummary,
    /// ISO 8601 timestamp of the verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Source that produced this verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Summary counts of indicator evaluation results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationSummary {
    /// Number of indicators that matched.
    pub matched: i64,
    /// Number of indicators that did not match.
    pub not_matched: i64,
    /// Number of indicators that errored.
    pub error: i64,
    /// Number of indicators that were skipped.
    pub skipped: i64,
}

// ─── §2.23 SynthesizeBlock ──────────────────────────────────────────────────

/// An LLM synthesis block for generating adversarial content.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SynthesizeBlock {
    /// Prompt template for the generation provider.
    pub prompt: String,
}

// ─── §2.24 ResponseEntry ────────────────────────────────────────────────────

/// A conditional response entry in a phase's state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseEntry {
    /// Predicate that selects this response (matched against the request).
    #[serde(rename = "when", skip_serializing_if = "Option::is_none")]
    pub when: Option<MatchPredicate>,
    /// LLM synthesis block for dynamic content generation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synthesize: Option<SynthesizeBlock>,
    /// Protocol-specific static content fields (MCP content, A2A messages, etc.).
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
