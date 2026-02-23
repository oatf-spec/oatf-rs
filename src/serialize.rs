//! [`Document`] → YAML serialization.

use crate::error::SerializeError;
use crate::types::Document;

/// Serialize a Document to a YAML string.
///
/// The document should typically be normalized before serialization.
/// The `oatf` field is emitted first, followed by `$schema` (if present),
/// then `attack` fields in specification order.
pub fn serialize(doc: &Document) -> Result<String, SerializeError> {
    // Convert to serde_json::Value first for consistent field ordering
    let value = serde_json::to_value(doc).map_err(|e| SerializeError {
        message: format!("failed to convert document to JSON value: {}", e),
    })?;

    // Serialize to YAML using serde-saphyr
    let yaml = serde_saphyr::to_string(&value).map_err(|e| SerializeError {
        message: format!("failed to serialize to YAML: {}", e),
    })?;

    Ok(yaml)
}
