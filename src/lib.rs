//! Rust SDK for the [Open Agent Threat Format (OATF)](https://oatf.io).
//!
//! OATF is a YAML-based format for describing security threats against AI agent
//! communication protocols (MCP, A2A, AG-UI). This crate provides a complete
//! pipeline for working with OATF documents:
//!
//! ```text
//! parse(yaml) → Document → validate(doc) → ValidationResult
//!                        → normalize(doc) → Document → serialize(doc) → yaml
//! ```
//!
//! # Quick Start
//!
//! ```rust
//! let yaml = r#"
//! oatf: "0.1"
//! attack:
//!   execution:
//!     mode: mcp_server
//!     phases:
//!       - name: exploit
//!         state:
//!           tools:
//!             - name: evil-tool
//!               description: "A malicious tool"
//!               inputSchema:
//!                 type: object
//!         trigger:
//!           event: tools/call
//!       - name: terminal
//!   indicators:
//!     - surface: tool_description
//!       pattern:
//!         contains: malicious
//! "#;
//!
//! let result = oatf::load(yaml).expect("valid document");
//! println!("Loaded: {:?}", result.document.attack.name);
//! ```
//!
//! # Feature Flags
//!
//! | Feature    | Default | Description |
//! |------------|---------|-------------|
//! | `cel-eval` | yes     | CEL expression evaluation via the [`cel`] crate. Enables [`evaluate::DefaultCelEvaluator`]. |

pub mod enums;
pub mod error;
pub mod evaluate;
pub mod normalize;
pub mod parse;
pub mod primitives;
pub mod serialize;
pub mod types;
pub mod validate;

pub(crate) mod event_registry;
pub(crate) mod surface;

pub use error::*;
pub use types::*;

// Re-export entry-point functions at the crate root for convenience.
pub use normalize::normalize;
pub use parse::parse;
pub use serialize::serialize;
pub use validate::validate;

/// Result of the [`load`] convenience entry point.
pub struct LoadResult {
    /// The normalized document.
    pub document: Document,
    /// Non-fatal warnings produced during validation.
    pub warnings: Vec<Diagnostic>,
}

/// Convenience entry point composing parse → validate → normalize.
///
/// Returns the normalized document and any warnings on success.
/// Returns all errors (parse or validation) on failure.
///
/// # Errors
///
/// Returns `Err(Vec<OATFError>)` if parsing fails or validation finds errors.
///
/// # Example
///
/// ```rust
/// let yaml = r#"
/// oatf: "0.1"
/// attack:
///   execution:
///     mode: mcp_server
///     phases:
///       - name: exploit
///         state:
///           tools:
///             - name: test-tool
///               description: "A test tool"
///               inputSchema:
///                 type: object
///         trigger:
///           event: tools/call
///       - name: terminal
///   indicators:
///     - surface: tool_description
///       pattern:
///         contains: test
/// "#;
///
/// match oatf::load(yaml) {
///     Ok(result) => println!("Loaded with {} warnings", result.warnings.len()),
///     Err(errors) => eprintln!("{} errors", errors.len()),
/// }
/// ```
pub fn load(input: &str) -> Result<LoadResult, Vec<OATFError>> {
    let doc = parse::parse(input).map_err(|e| vec![OATFError::Parse(e)])?;

    let result = validate::validate(&doc);
    if !result.errors.is_empty() {
        return Err(result
            .errors
            .into_iter()
            .map(OATFError::Validation)
            .collect());
    }

    let normalized = normalize::normalize(doc);

    Ok(LoadResult {
        document: normalized,
        warnings: result.warnings,
    })
}
