use serde::{Deserialize, Serialize};
use std::fmt;

/// Diagnostic severity level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
}

/// A structured diagnostic message produced during validation, normalization, or evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub message: String,
}

/// Error kind for parse failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseErrorKind {
    Syntax,
    TypeMismatch,
    UnknownVariant,
}

/// Produced by `parse` when YAML deserialization fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
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
    pub rule: String,
    pub path: String,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.rule, self.path, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Result of validation: errors and warnings.
#[derive(Clone, Debug, Default)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
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
    PathResolution,
    RegexTimeout,
    CelError,
    TypeError,
    SemanticError,
    UnsupportedMethod,
}

/// Produced during indicator evaluation when a runtime error occurs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationError {
    pub kind: EvaluationErrorKind,
    pub message: String,
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
    ProviderUnavailable,
    ModelError,
    ValidationFailure,
    Timeout,
    ContentPolicy,
}

/// Produced by a GenerationProvider when LLM synthesis fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationError {
    pub kind: GenerationErrorKind,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase_name: Option<String>,
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
    Parse(ParseError),
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
