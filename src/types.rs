use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;

use crate::enums::*;

// ─── §2.2 Document ──────────────────────────────────────────────────────────

/// The top-level container for a parsed OATF document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Document {
    pub oatf: String,
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub attack: Attack,
}

// ─── §2.3 Attack ─────────────────────────────────────────────────────────────

/// The attack envelope and all contained structures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attack {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<Vec<Impact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classification: Option<Classification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<Reference>>,
    pub execution: Execution,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicators: Option<Vec<Indicator>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation: Option<Correlation>,
    /// Extension fields (x-* prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.3a Correlation ───────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Correlation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logic: Option<CorrelationLogic>,
}

// ─── §2.4 Severity ───────────────────────────────────────────────────────────

/// Severity can be either a scalar string or an object form.
/// During deserialization, a bare string like "high" is accepted.
/// After normalization, always in object form.
#[derive(Clone, Debug)]
pub enum Severity {
    Scalar(SeverityLevel),
    Object { level: SeverityLevel, confidence: Option<i64> },
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Classification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Vec<FrameworkMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

// ─── §2.6 Execution ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phases: Option<Vec<Phase>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<Actor>>,
    /// Extension fields (x-* prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.6a Actor ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Actor {
    pub name: String,
    pub mode: String,
    pub phases: Vec<Phase>,
    /// Extension fields (x-* prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.7 Phase ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Phase {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extractors: Option<Vec<Extractor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_enter: Option<Vec<Action>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<Trigger>,
    /// Extension fields (x-* prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.7a Action ────────────────────────────────────────────────────────────

/// An entry action executed when a phase begins.
/// Tagged union with known variants + catch-all for binding-specific actions.
#[derive(Clone, Debug)]
pub enum Action {
    SendNotification {
        method: String,
        params: Option<Value>,
        extensions: HashMap<String, Value>,
    },
    Log {
        message: String,
        level: Option<LogLevel>,
        extensions: HashMap<String, Value>,
    },
    SendElicitation {
        message: String,
        mode: Option<ElicitationMode>,
        #[allow(non_snake_case)]
        requested_schema: Option<Value>,
        url: Option<String>,
        extensions: HashMap<String, Value>,
    },
    /// Binding-specific action with a single unknown key.
    BindingSpecific {
        key: String,
        value: Value,
        extensions: HashMap<String, Value>,
    },
}

impl Serialize for Action {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Action::SendNotification { method, params, extensions } => {
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
            Action::Log { message, level, extensions } => {
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
            Action::BindingSpecific { key, value, extensions } => {
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
        let map: serde_json::Map<String, Value> =
            serde_json::Map::deserialize(deserializer)?;

        let mut extensions = HashMap::new();
        let mut action_key = None;
        let mut action_value = None;

        for (k, v) in &map {
            if k.starts_with("x-") {
                extensions.insert(k.clone(), v.clone());
            } else if action_key.is_none() {
                action_key = Some(k.clone());
                action_value = Some(v.clone());
            } else {
                // Multiple non-x- keys — store as binding specific with first key
                // V-043 will catch this during validation
                // For parsing, just grab the first one
            }
        }

        let key = action_key
            .ok_or_else(|| serde::de::Error::custom("action object must have at least one key"))?;
        let value = action_value.unwrap();

        match key.as_str() {
            "send_notification" => {
                let obj = value
                    .as_object()
                    .ok_or_else(|| serde::de::Error::custom("send_notification must be an object"))?;
                let method = obj
                    .get("method")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("send_notification requires 'method'"))?
                    .to_string();
                let params = obj.get("params").cloned();
                Ok(Action::SendNotification { method, params, extensions })
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
                Ok(Action::Log { message, level, extensions })
            }
            "send_elicitation" => {
                let obj = value
                    .as_object()
                    .ok_or_else(|| serde::de::Error::custom("send_elicitation must be an object"))?;
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
                let url = obj.get("url").and_then(|v| v.as_str()).map(|s| s.to_string());
                Ok(Action::SendElicitation {
                    message,
                    mode,
                    requested_schema,
                    url,
                    extensions,
                })
            }
            _ => {
                // Binding-specific action or multiple non-x- keys
                // Collect all non-x- keys to detect V-043 violations later
                let non_ext_keys: Vec<_> = map.keys().filter(|k| !k.starts_with("x-")).collect();
                if non_ext_keys.len() == 1 {
                    Ok(Action::BindingSpecific { key, value, extensions })
                } else {
                    // Still parse it — V-043 will catch the error
                    Ok(Action::BindingSpecific { key, value, extensions })
                }
            }
        }
    }
}

// ─── §2.8 Trigger ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trigger {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    pub match_predicate: Option<MatchPredicate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

// ─── §2.8a ProtocolEvent ─────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolEvent {
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    pub content: Value,
}

// ─── §2.8b TriggerResult ────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriggerResult {
    Advanced { reason: AdvanceReason },
    NotAdvanced,
}

// ─── §2.9 Extractor ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Extractor {
    pub name: String,
    pub source: ExtractorSource,
    #[serde(rename = "type")]
    pub extractor_type: ExtractorType,
    pub selector: String,
}

// ─── §2.10 MatchPredicate ───────────────────────────────────────────────────

/// A match predicate is a map from dot-path field references to conditions.
pub type MatchPredicate = HashMap<String, MatchEntry>;

/// Either a scalar Value (equality check) or a MatchCondition object.
#[derive(Clone, Debug)]
pub enum MatchEntry {
    Scalar(Value),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MatchCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starts_with: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ends_with: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_of: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gt: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lt: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gte: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lte: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exists: Option<bool>,
}

// ─── §2.12 Indicator ────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Indicator {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    pub surface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<PatternMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<ExpressionMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<SeverityLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub false_positives: Option<Vec<String>>,
    /// Extension fields (x-* prefixed).
    #[serde(flatten)]
    pub extensions: HashMap<String, Value>,
}

// ─── §2.13 PatternMatch ─────────────────────────────────────────────────────

/// A pattern match indicator. Supports standard and shorthand form.
/// In standard form: has `target` and `condition`.
/// In shorthand form: has operator keys directly (e.g., `contains`, `regex`).
#[derive(Clone, Debug)]
pub struct PatternMatch {
    pub target: Option<String>,
    pub condition: Option<Condition>,
    // Shorthand operator fields (before normalization)
    pub contains: Option<String>,
    pub starts_with: Option<String>,
    pub ends_with: Option<String>,
    pub regex: Option<String>,
    pub any_of: Option<Vec<Value>>,
    pub gt: Option<f64>,
    pub lt: Option<f64>,
    pub gte: Option<f64>,
    pub lte: Option<f64>,
}

impl PatternMatch {
    /// Returns true if this pattern is in shorthand form (has direct operator keys).
    pub fn is_shorthand(&self) -> bool {
        self.condition.is_none()
            && (self.contains.is_some()
                || self.starts_with.is_some()
                || self.ends_with.is_some()
                || self.regex.is_some()
                || self.any_of.is_some()
                || self.gt.is_some()
                || self.lt.is_some()
                || self.gte.is_some()
                || self.lte.is_some())
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

        let target = map.get("target").and_then(|v| v.as_str()).map(|s| s.to_string());
        let condition = map.get("condition").map(|v| {
            // Condition can be a bare value or a MatchCondition object
            Condition::from_value(v.clone())
        });

        // Shorthand operator fields
        let contains = map.get("contains").and_then(|v| v.as_str()).map(|s| s.to_string());
        let starts_with = map.get("starts_with").and_then(|v| v.as_str()).map(|s| s.to_string());
        let ends_with = map.get("ends_with").and_then(|v| v.as_str()).map(|s| s.to_string());
        let regex = map.get("regex").and_then(|v| v.as_str()).map(|s| s.to_string());
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
    Equality(Value),
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
                if map.keys().any(|k| operator_keys.contains(&k.as_str())) {
                    if let Ok(cond) = serde_json::from_value::<MatchCondition>(v.clone()) {
                        return Condition::Operators(cond);
                    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpressionMatch {
    pub cel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variables: Option<HashMap<String, String>>,
}

// ─── §2.15 SemanticMatch ────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticMatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub intent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_class: Option<SemanticIntentClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub examples: Option<SemanticExamples>,
}

// ─── §2.16 SemanticExamples ─────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticExamples {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub positive: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negative: Option<Vec<String>>,
}

// ─── §2.17 Reference ────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reference {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ─── §2.18 FrameworkMapping ─────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameworkMapping {
    pub framework: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<Relationship>,
}

// ─── §2.19 Verdict Types ────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndicatorVerdict {
    pub indicator_id: String,
    pub result: IndicatorResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttackVerdict {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_id: Option<String>,
    pub result: AttackResult,
    pub indicator_verdicts: Vec<IndicatorVerdict>,
    pub evaluation_summary: EvaluationSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvaluationSummary {
    pub matched: i64,
    pub not_matched: i64,
    pub error: i64,
    pub skipped: i64,
}

// ─── §2.23 SynthesizeBlock ──────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SynthesizeBlock {
    pub prompt: String,
}

// ─── §2.24 ResponseEntry ────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseEntry {
    #[serde(rename = "when", skip_serializing_if = "Option::is_none")]
    pub when: Option<MatchPredicate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synthesize: Option<SynthesizeBlock>,
    // Protocol-specific static content fields are captured as extra fields
    // via serde(flatten) to support MCP content, MCP messages, A2A messages/artifacts
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
