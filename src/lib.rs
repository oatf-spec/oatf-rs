//! OATF SDK — Parse, validate, normalize, and serialize
//! Open Agent Threat Format documents.

pub mod enums;
pub mod error;
pub mod event_registry;
pub mod normalize;
pub mod parse;
pub mod primitives;
pub mod serialize;
pub mod surface;
pub mod types;
pub mod validate;

pub use error::*;
pub use types::*;

/// Result of the `load` convenience entry point.
pub struct LoadResult {
    pub document: Document,
    pub warnings: Vec<Diagnostic>,
}

/// Convenience entry point composing parse → validate → normalize.
///
/// If parse fails, returns parse errors.
/// If validate finds errors, returns validation errors.
/// If both succeed, returns the normalized document with any warnings.
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
