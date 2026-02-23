//! Closed enumerations used throughout the OATF type system.
//!
//! These are "closed" enums — only the defined variants are valid. Open enums
//! (mode, protocol) are represented as strings and validated by regex pattern.

use serde::{Deserialize, Serialize};

/// Severity classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityLevel {
    /// Advisory or informational finding.
    Informational,
    /// Low-severity finding.
    Low,
    /// Medium-severity finding.
    Medium,
    /// High-severity finding.
    High,
    /// Critical-severity finding requiring immediate attention.
    Critical,
}

/// Categories of harm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    /// Agent behavior is manipulated by an adversary.
    BehaviorManipulation,
    /// Sensitive data is exfiltrated through agent actions.
    DataExfiltration,
    /// Data integrity is compromised through unauthorized modifications.
    DataTampering,
    /// Agent performs actions without proper authorization.
    UnauthorizedActions,
    /// Sensitive information is disclosed to unauthorized parties.
    InformationDisclosure,
    /// Credentials or authentication tokens are stolen.
    CredentialTheft,
    /// Agent or service availability is disrupted.
    ServiceDisruption,
    /// Attacker gains elevated privileges.
    PrivilegeEscalation,
}

/// OATF taxonomy category.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Manipulation of agent capabilities or tool definitions.
    CapabilityPoisoning,
    /// Fabrication of responses to mislead the agent.
    ResponseFabrication,
    /// Manipulation of the agent's context or conversation state.
    ContextManipulation,
    /// Bypassing human oversight or approval mechanisms.
    OversightBypass,
    /// Exploiting timing or ordering of operations.
    TemporalManipulation,
    /// Disrupting service availability.
    AvailabilityDisruption,
    /// Chaining attacks across multiple protocols.
    CrossProtocolChain,
}

/// Document lifecycle status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Work in progress, not yet validated.
    Draft,
    /// Under evaluation, may change.
    Experimental,
    /// Validated and stable.
    Stable,
    /// No longer recommended for use.
    Deprecated,
}

/// How indicator verdicts combine into an attack-level result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationLogic {
    /// Any matched indicator produces an `exploited` verdict.
    Any,
    /// All indicators must match for an `exploited` verdict.
    All,
}

/// Individual indicator evaluation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorResult {
    /// The indicator matched the observed data.
    Matched,
    /// The indicator did not match.
    NotMatched,
    /// An error occurred during evaluation.
    Error,
    /// Evaluation was skipped (e.g., no evaluator available).
    Skipped,
}

/// Attack-level verdict result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackResult {
    /// The attack was successfully exploited.
    Exploited,
    /// The attack was not exploited.
    NotExploited,
    /// Some but not all indicators matched (`all` correlation only).
    Partial,
    /// An error occurred during verdict computation.
    Error,
}

/// Extractor source direction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractorSource {
    /// Extract from the protocol request message.
    Request,
    /// Extract from the protocol response message.
    Response,
}

/// Extractor type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractorType {
    /// Extract values using a JSONPath expression.
    JsonPath,
    /// Extract values using a regular expression.
    Regex,
}

/// Semantic intent classification hint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticIntentClass {
    /// Attempt to inject instructions into the agent's prompt.
    PromptInjection,
    /// Attempt to exfiltrate data through the agent.
    DataExfiltration,
    /// Attempt to escalate privileges.
    PrivilegeEscalation,
    /// Attempt to manipulate through social engineering.
    SocialEngineering,
    /// Attempt to override the agent's instructions.
    InstructionOverride,
}

/// Framework mapping relationship type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    /// Direct primary mapping to the framework entry.
    Primary,
    /// Related but not primary mapping.
    Related,
}

/// Log level for log actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Informational log message.
    Info,
    /// Warning log message.
    Warn,
    /// Error log message.
    Error,
}

/// Elicitation mode for user interaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElicitationMode {
    /// Display an interactive form to the user.
    Form,
    /// Redirect the user to a URL.
    Url,
}

/// Reason a trigger advanced to the next phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvanceReason {
    /// The trigger's event condition was matched.
    EventMatched,
    /// The trigger's timeout elapsed.
    Timeout,
}
