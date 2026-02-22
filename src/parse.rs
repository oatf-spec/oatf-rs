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
    let oatf_is_first_key = if let Some(obj) = value.as_object() {
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
        obj.keys().next().map(|k| k == "oatf").unwrap_or(false)
    } else {
        false
    };

    // Convert serde_json::Value to Document
    let mut doc: Document = serde_json::from_value(value).map_err(|e| {
        let msg = e.to_string();
        ParseError {
            kind: classify_json_error(&msg),
            message: msg,
            path: None,
            line: None,
            column: None,
        }
    })?;

    doc.oatf_is_first_key = oatf_is_first_key;

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
/// Tracks block scalar state to skip content inside `|` and `>` blocks.
fn check_yaml_anchors_aliases(input: &str) -> Result<(), ParseError> {
    let lines: Vec<&str> = input.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }

        // Check if this line introduces a block scalar (value ends with |, >, |-, |+, >-, >+)
        if line_introduces_block_scalar(trimmed) {
            i = skip_block_scalar(&lines, i);
            continue;
        }

        let in_content = strip_yaml_string_literals(trimmed);

        // Check for merge keys
        if in_content.contains("<<:") || in_content.contains("<< :") {
            return Err(ParseError {
                kind: ParseErrorKind::Syntax,
                message: "YAML merge keys (<<) are not allowed in OATF documents".to_string(),
                path: None,
                line: Some(i + 1),
                column: None,
            });
        }

        // Check for anchors: & at start of value position
        if let Some(pos) = find_yaml_anchor(&in_content) {
            return Err(ParseError {
                kind: ParseErrorKind::Syntax,
                message: "YAML anchors (&) are not allowed in OATF documents".to_string(),
                path: None,
                line: Some(i + 1),
                column: Some(pos + 1),
            });
        }

        // Check for aliases: * at start of value position
        if let Some(pos) = find_yaml_alias(&in_content) {
            return Err(ParseError {
                kind: ParseErrorKind::Syntax,
                message: "YAML aliases (*) are not allowed in OATF documents".to_string(),
                path: None,
                line: Some(i + 1),
                column: Some(pos + 1),
            });
        }

        i += 1;
    }
    Ok(())
}

/// Check if a trimmed YAML line's value ends with a block scalar indicator.
fn line_introduces_block_scalar(trimmed: &str) -> bool {
    // A block scalar is introduced when a mapping value (after `:`) or sequence entry (after `- `)
    // ends with |, >, |-, |+, >-, >+ (possibly followed by a comment).
    // Find the value part after the colon (for mappings)
    let value_part = if let Some(colon_pos) = find_colon_in_yaml(trimmed) {
        trimmed[colon_pos + 1..].trim()
    } else if trimmed.starts_with("- ") {
        trimmed[2..].trim()
    } else {
        return false;
    };

    // Strip trailing comment
    let value_no_comment = strip_trailing_comment(value_part);
    let v = value_no_comment.trim();

    matches!(v, "|" | ">" | "|-" | "|+" | ">-" | ">+")
}

/// Find the position of the key-value colon in a YAML line, skipping quoted strings.
fn find_colon_in_yaml(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' { i += 2; continue; }
                    if bytes[i] == b'"' { i += 1; break; }
                    i += 1;
                }
            }
            b'\'' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\'' {
                        i += 1;
                        if i < bytes.len() && bytes[i] == b'\'' { i += 1; } else { break; }
                    } else {
                        i += 1;
                    }
                }
            }
            b':' if i + 1 >= bytes.len() || bytes[i + 1] == b' ' || bytes[i + 1] == b'\t' => {
                return Some(i);
            }
            _ => { i += 1; }
        }
    }
    None
}

/// Strip trailing YAML comment (# ...) from a value, respecting quotes.
fn strip_trailing_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' { i += 2; continue; }
                    if bytes[i] == b'"' { i += 1; break; }
                    i += 1;
                }
            }
            b'\'' => {
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\'' {
                        i += 1;
                        if i < bytes.len() && bytes[i] == b'\'' { i += 1; }
                        else { break; }
                    } else {
                        i += 1;
                    }
                }
            }
            b' ' if i + 1 < bytes.len() && bytes[i + 1] == b'#' => {
                return &value[..i];
            }
            b'#' if i == 0 => {
                return "";
            }
            _ => { i += 1; }
        }
    }
    value
}

/// Skip all lines belonging to a block scalar starting at `start_idx`.
/// Returns the index of the first line after the block.
fn skip_block_scalar(lines: &[&str], start_idx: usize) -> usize {
    // The block scalar content indent is determined by the first non-empty line after the header.
    let mut i = start_idx + 1;

    // Find the content indent from the first non-empty content line
    let content_indent = loop {
        if i >= lines.len() {
            return i;
        }
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        // Count leading spaces
        let indent = line.len() - line.trim_start().len();
        break indent;
    };

    // The header line's indent level
    let header_indent = lines[start_idx].len() - lines[start_idx].trim_start().len();

    // Content must be indented more than the header
    if content_indent <= header_indent {
        return start_idx + 1;
    }

    // Skip all lines that are either empty or indented at content_indent or deeper
    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent >= content_indent {
            i += 1;
        } else {
            break;
        }
    }
    i
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
