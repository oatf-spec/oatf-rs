//! Error and diagnostic types for parse, validation, evaluation, and serialization.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Diagnostic severity level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// A conformance error that must be fixed.
    Error,
    /// A non-fatal warning (W-rules).
    Warning,
}

/// A structured diagnostic message produced during validation, normalization, or evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Whether this is an error or warning.
    pub severity: DiagnosticSeverity,
    /// Rule identifier (e.g., `"W-001"`).
    pub code: String,
    /// JSONPath to the offending element, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Error kind for parse failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseErrorKind {
    /// YAML syntax error or structural issue.
    Syntax,
    /// Value has the wrong type for the expected field.
    TypeMismatch,
    /// An unrecognized enum variant or key was encountered.
    UnknownVariant,
}

/// Produced by `parse` when YAML deserialization fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    /// Classification of the parse failure.
    pub kind: ParseErrorKind,
    /// Human-readable error description.
    pub message: String,
    /// JSONPath to the element that caused the error, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 1-based line number in the YAML source, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// 1-based column number in the YAML source, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(line), Some(col)) = (self.line, self.column) {
            write!(f, "{}:{}: {}", line, col, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for ParseError {}

/// Produced by `validate` when a document violates a conformance rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationError {
    /// Conformance rule identifier (e.g., `"V-001"`).
    pub rule: String,
    /// Specification section reference (e.g., `"§11.1.1"`).
    pub spec_ref: String,
    /// JSONPath to the offending element.
    pub path: String,
    /// Human-readable description of the violation.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) at {}: {}",
            self.rule, self.spec_ref, self.path, self.message
        )
    }
}

impl std::error::Error for ValidationError {}

/// Result of validation: errors and warnings.
#[derive(Clone, Debug, Default)]
pub struct ValidationResult {
    /// Conformance rule violations (V-rules).
    pub errors: Vec<ValidationError>,
    /// Non-fatal warnings (W-rules).
    pub warnings: Vec<Diagnostic>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Error kind for evaluation failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationErrorKind {
    /// JSONPath or target path could not be resolved.
    PathResolution,
    /// A regex evaluation timed out.
    RegexTimeout,
    /// CEL compilation or execution error.
    CelError,
    /// Result was not the expected type (e.g., non-boolean CEL result).
    TypeError,
    /// Semantic evaluator returned an error.
    SemanticError,
    /// The CEL expression used an unsupported method.
    UnsupportedMethod,
}

/// Produced during indicator evaluation when a runtime error occurs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationError {
    /// Classification of the evaluation failure.
    pub kind: EvaluationErrorKind,
    /// Human-readable error description.
    pub message: String,
    /// Indicator that caused the error, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicator_id: Option<String>,
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EvaluationError {}

/// Error kind for generation failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationErrorKind {
    /// The generation provider is not available.
    ProviderUnavailable,
    /// The underlying model returned an error.
    ModelError,
    /// The generated content failed validation.
    ValidationFailure,
    /// The generation request timed out.
    Timeout,
    /// The request was rejected by a content policy.
    ContentPolicy,
}

/// Produced by a GenerationProvider when LLM synthesis fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationError {
    /// Classification of the generation failure.
    pub kind: GenerationErrorKind,
    /// Human-readable error description.
    pub message: String,
    /// Phase name where generation was attempted, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase_name: Option<String>,
    /// Truncated prompt used for the generation attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_preview: Option<String>,
}

impl fmt::Display for GenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for GenerationError {}

/// Serialization error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializeError {
    /// Human-readable error description.
    pub message: String,
}

impl fmt::Display for SerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SerializeError {}

/// Combined error type for the `load` entry point.
#[derive(Clone, Debug)]
pub enum OATFError {
    /// A parse-stage error.
    Parse(ParseError),
    /// A validation-stage error (first error encountered).
    Validation(ValidationError),
}

impl fmt::Display for OATFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OATFError::Parse(e) => write!(f, "Parse error: {}", e),
            OATFError::Validation(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::error::Error for OATFError {}
