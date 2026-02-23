//! Closed enumerations used throughout the OATF type system.
//!
//! These are "closed" enums — only the defined variants are valid. Open enums
//! (mode, protocol) are represented as strings and validated by regex pattern.

use serde::{Deserialize, Serialize};

/// Severity classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityLevel {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Categories of harm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    BehaviorManipulation,
    DataExfiltration,
    DataTampering,
    UnauthorizedActions,
    InformationDisclosure,
    CredentialTheft,
    ServiceDisruption,
    PrivilegeEscalation,
}

/// OATF taxonomy category.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    CapabilityPoisoning,
    ResponseFabrication,
    ContextManipulation,
    OversightBypass,
    TemporalManipulation,
    AvailabilityDisruption,
    CrossProtocolChain,
}

/// Document lifecycle status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Draft,
    Experimental,
    Stable,
    Deprecated,
}

/// How indicator verdicts combine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationLogic {
    Any,
    All,
}

/// Individual indicator result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorResult {
    Matched,
    NotMatched,
    Error,
    Skipped,
}

/// Attack-level verdict result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackResult {
    Exploited,
    NotExploited,
    Partial,
    Error,
}

/// Extractor source direction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractorSource {
    Request,
    Response,
}

/// Extractor type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractorType {
    JsonPath,
    Regex,
}

/// Semantic intent classification hint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticIntentClass {
    PromptInjection,
    DataExfiltration,
    PrivilegeEscalation,
    SocialEngineering,
    InstructionOverride,
}

/// Framework mapping relationship.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    Primary,
    Related,
}

/// Log level for log actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

/// Elicitation mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElicitationMode {
    Form,
    Url,
}

/// Trigger advance reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvanceReason {
    EventMatched,
    Timeout,
}
