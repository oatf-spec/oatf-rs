use crate::error::{ParseError, ParseErrorKind};
use crate::types::Document;

/// Parse a YAML string into an unvalidated Document.
///
/// Performs YAML deserialization and type mapping only.
/// Does NOT validate document conformance or apply normalization.
pub fn parse(input: &str) -> Result<Document, ParseError> {
    if input.trim().is_empty() {
        return Err(ParseError {
            kind: ParseErrorKind::Syntax,
            message: "empty input".to_string(),
            path: None,
            line: None,
            column: None,
        });
    }

    // Check for YAML anchors, aliases, and merge keys (V-020)
    // We do a pre-scan of the raw text for anchor/alias markers
    check_yaml_anchors_aliases(input)?;

    // Check for multi-document YAML (multiple --- markers)
    check_multi_document(input)?;

    // Deserialize using serde-saphyr via serde_json Value as intermediate
    // First parse YAML to serde_json::Value, then convert to Document
    let value: serde_json::Value = serde_saphyr::from_str(input).map_err(|e| {
        let msg = e.to_string();
        // Try to extract location info from the error message
        ParseError {
            kind: classify_saphyr_error(&msg),
            message: msg,
            path: None,
            line: None,
            column: None,
        }
    })?;

    // Ensure root is a mapping/object
    if !value.is_object() {
        return Err(ParseError {
            kind: ParseErrorKind::TypeMismatch,
            message: "document root must be a YAML mapping".to_string(),
            path: None,
            line: None,
            column: None,
        });
    }

    // Validate no unknown top-level keys (only oatf, $schema, attack allowed)
    if let Some(obj) = value.as_object() {
        for key in obj.keys() {
            match key.as_str() {
                "oatf" | "$schema" | "attack" => {}
                other => {
                    return Err(ParseError {
                        kind: ParseErrorKind::TypeMismatch,
                        message: format!("unknown top-level field: {}", other),
                        path: Some(other.to_string()),
                        line: None,
                        column: None,
                    });
                }
            }
        }
    }

    // Convert serde_json::Value to Document
    let doc: Document = serde_json::from_value(value).map_err(|e| {
        let msg = e.to_string();
        ParseError {
            kind: classify_json_error(&msg),
            message: msg,
            path: None,
            line: None,
            column: None,
        }
    })?;

    // Validate extension fields (only x-* prefixed keys allowed)
    validate_extension_keys(&doc)?;

    Ok(doc)
}

/// Validate that all extension (flatten) fields start with "x-".
fn validate_extension_keys(doc: &Document) -> Result<(), ParseError> {
    check_extensions(&doc.attack.extensions, "attack")?;
    check_extensions(&doc.attack.execution.extensions, "attack.execution")?;

    if let Some(actors) = &doc.attack.execution.actors {
        for (i, actor) in actors.iter().enumerate() {
            check_extensions(&actor.extensions, &format!("attack.execution.actors[{}]", i))?;
            for (j, phase) in actor.phases.iter().enumerate() {
                check_extensions(
                    &phase.extensions,
                    &format!("attack.execution.actors[{}].phases[{}]", i, j),
                )?;
            }
        }
    }

    if let Some(phases) = &doc.attack.execution.phases {
        for (j, phase) in phases.iter().enumerate() {
            check_extensions(&phase.extensions, &format!("attack.execution.phases[{}]", j))?;
        }
    }

    if let Some(indicators) = &doc.attack.indicators {
        for (i, ind) in indicators.iter().enumerate() {
            check_extensions(&ind.extensions, &format!("attack.indicators[{}]", i))?;
        }
    }

    Ok(())
}

fn check_extensions(
    extensions: &std::collections::HashMap<String, serde_json::Value>,
    path: &str,
) -> Result<(), ParseError> {
    for key in extensions.keys() {
        if !key.starts_with("x-") {
            return Err(ParseError {
                kind: ParseErrorKind::TypeMismatch,
                message: format!("unknown field '{}' at {} (non-extension fields must not use reserved names; extension fields must start with 'x-')", key, path),
                path: Some(format!("{}.{}", path, key)),
                line: None,
                column: None,
            });
        }
    }
    Ok(())
}

/// Check for YAML anchors (&), aliases (*), and merge keys (<<).
fn check_yaml_anchors_aliases(input: &str) -> Result<(), ParseError> {
    for (line_num, line) in input.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments
        if trimmed.starts_with('#') {
            continue;
        }

        // Check for anchors: & followed by identifier (not inside quotes)
        // Check for aliases: * followed by identifier (not inside quotes or glob patterns)
        // Check for merge keys: <<
        // We need to be careful not to match & and * inside quoted strings

        let in_content = strip_yaml_string_literals(trimmed);

        // Check for merge keys
        if in_content.contains("<<:") || in_content.contains("<< :") {
            return Err(ParseError {
                kind: ParseErrorKind::Syntax,
                message: "YAML merge keys (<<) are not allowed in OATF documents".to_string(),
                path: None,
                line: Some(line_num + 1),
                column: None,
            });
        }

        // Check for anchors: & at start of value position
        if let Some(pos) = find_yaml_anchor(&in_content) {
            return Err(ParseError {
                kind: ParseErrorKind::Syntax,
                message: "YAML anchors (&) are not allowed in OATF documents".to_string(),
                path: None,
                line: Some(line_num + 1),
                column: Some(pos + 1),
            });
        }

        // Check for aliases: * at start of value position
        if let Some(pos) = find_yaml_alias(&in_content) {
            return Err(ParseError {
                kind: ParseErrorKind::Syntax,
                message: "YAML aliases (*) are not allowed in OATF documents".to_string(),
                path: None,
                line: Some(line_num + 1),
                column: Some(pos + 1),
            });
        }
    }
    Ok(())
}

/// Find YAML anchor (&name) in a line, returning position if found.
/// Requires `&` to be in value position (preceded by space, colon, dash, or at line start)
/// to avoid false positives on URLs and other content containing `&`.
fn find_yaml_anchor(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            // Check if followed by a valid YAML anchor character
            if i + 1 < bytes.len()
                && is_yaml_anchor_char(bytes[i + 1])
                && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b':' || bytes[i - 1] == b'-')
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Find YAML alias (*name) in a line, returning position if found.
fn find_yaml_alias(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'*' {
            // Check if preceded by space or start of line, and followed by anchor char
            if i + 1 < bytes.len()
                && is_yaml_anchor_char(bytes[i + 1])
                && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b':' || bytes[i - 1] == b'-')
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn is_yaml_anchor_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Strip string literals from a YAML line for anchor/alias detection.
fn strip_yaml_string_literals(line: &str) -> String {
    let mut result = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                // Skip double-quoted string
                result.push(' ');
                loop {
                    match chars.next() {
                        Some('\\') => {
                            chars.next(); // skip escaped char
                        }
                        Some('"') | None => break,
                        _ => {}
                    }
                }
            }
            '\'' => {
                // Skip single-quoted string
                result.push(' ');
                loop {
                    match chars.next() {
                        Some('\'') => {
                            if chars.peek() == Some(&'\'') {
                                chars.next(); // escaped single quote
                            } else {
                                break;
                            }
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
            _ => result.push(c),
        }
    }
    result
}

/// Check for multiple YAML documents (--- separator).
/// Only matches `---` at column 0 to avoid false positives inside block scalars.
fn check_multi_document(input: &str) -> Result<(), ParseError> {
    let mut doc_count = 0;
    for line in input.lines() {
        // Document markers must start at column 0 per YAML spec
        if line.starts_with("---") && line[3..].trim().is_empty() {
            doc_count += 1;
            if doc_count > 1 {
                return Err(ParseError {
                    kind: ParseErrorKind::Syntax,
                    message: "multi-document YAML is not supported".to_string(),
                    path: None,
                    line: None,
                    column: None,
                });
            }
        }
    }
    Ok(())
}

fn classify_saphyr_error(msg: &str) -> ParseErrorKind {
    let lower = msg.to_lowercase();
    if lower.contains("unknown") || lower.contains("variant") {
        ParseErrorKind::UnknownVariant
    } else if lower.contains("type") || lower.contains("invalid") || lower.contains("expected") {
        ParseErrorKind::TypeMismatch
    } else {
        ParseErrorKind::Syntax
    }
}

fn classify_json_error(msg: &str) -> ParseErrorKind {
    let lower = msg.to_lowercase();
    if lower.contains("unknown variant") || lower.contains("unknown field") {
        ParseErrorKind::UnknownVariant
    } else if lower.contains("missing field") || lower.contains("invalid type") {
        ParseErrorKind::TypeMismatch
    } else {
        ParseErrorKind::Syntax
    }
}
