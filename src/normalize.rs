use crate::enums::*;
use crate::event_registry::extract_protocol;
use crate::surface::lookup_surface;
use crate::types::*;

/// Normalize a validated document into its canonical fully-expanded form.
/// All defaults are materialized, all shorthand forms are expanded,
/// and all inferrable fields are computed.
///
/// This is idempotent: `normalize(normalize(doc)) == normalize(doc)`.
pub fn normalize(mut doc: Document) -> Document {
    // N-006 and N-007 MUST run early so all per-actor logic sees consistent multi-actor structure
    n006_single_phase_to_multi_actor(&mut doc);
    n007_multi_phase_to_multi_actor(&mut doc);

    // N-001: Apply defaults
    n001_defaults(&mut doc);

    // N-002: Expand severity scalar to object form
    n002_severity_expansion(&mut doc);

    // N-003: Auto-generate indicator IDs
    n003_auto_generate_indicator_ids(&mut doc);

    // N-004: Resolve pattern/semantic targets from surface registry
    n004_resolve_targets(&mut doc);

    // N-005: Expand pattern shorthand to standard form
    n005_expand_pattern_shorthand(&mut doc);

    // N-008: Apply MCP tool field defaults
    n008_mcp_tool_defaults(&mut doc);

    doc
}

// ─── N-001: Default values ───────────────────────────────────────────────────

fn n001_defaults(doc: &mut Document) {
    let attack = &mut doc.attack;

    // name → "Untitled"
    if attack.name.is_none() {
        attack.name = Some("Untitled".to_string());
    }

    // version → 1
    if attack.version.is_none() {
        attack.version = Some(1);
    }

    // status → draft
    if attack.status.is_none() {
        attack.status = Some(Status::Draft);
    }

    // severity.confidence → 50 (when severity is present)
    if let Some(ref mut severity) = attack.severity {
        match severity {
            Severity::Object {
                confidence: c,
                ..
            } => {
                if c.is_none() {
                    *c = Some(50);
                }
            }
            Severity::Scalar(_) => {
                // Will be expanded by N-002
            }
        }
    }

    // Phase names, modes, trigger counts
    if let Some(actors) = &mut attack.execution.actors {
        for actor in actors.iter_mut() {
            for (i, phase) in actor.phases.iter_mut().enumerate() {
                // phase.name → "phase-{N}" (1-based)
                if phase.name.is_none() {
                    phase.name = Some(format!("phase-{}", i + 1));
                }

                // trigger.count → 1 (when event present and count absent)
                if let Some(ref mut trigger) = phase.trigger {
                    if trigger.event.is_some() && trigger.count.is_none() {
                        trigger.count = Some(1);
                    }
                }
            }
        }
    }

    // indicator.protocol → protocol component of resolved mode
    if let Some(indicators) = &mut attack.indicators {
        let exec_protocol = attack
            .execution
            .mode
            .as_deref()
            .map(extract_protocol)
            .map(|s| s.to_string());

        // In multi-actor form after normalization, we may not have execution.mode
        // If actors exist, check for a single default actor
        let actor_protocol = attack
            .execution
            .actors
            .as_ref()
            .and_then(|actors| {
                if actors.len() == 1 {
                    Some(extract_protocol(&actors[0].mode).to_string())
                } else {
                    None
                }
            });

        let default_protocol = exec_protocol.or(actor_protocol);

        for ind in indicators.iter_mut() {
            if ind.protocol.is_none() {
                if let Some(ref proto) = default_protocol {
                    ind.protocol = Some(proto.clone());
                }
            }
        }
    }

    // correlation.logic → any (when indicators present)
    if attack.indicators.is_some() {
        if attack.correlation.is_none() {
            attack.correlation = Some(Correlation {
                logic: Some(CorrelationLogic::Any),
            });
        } else if let Some(ref mut corr) = attack.correlation {
            if corr.logic.is_none() {
                corr.logic = Some(CorrelationLogic::Any);
            }
        }
    }

    // mapping.relationship → "primary"
    if let Some(ref mut classification) = attack.classification {
        if let Some(ref mut mappings) = classification.mappings {
            for mapping in mappings.iter_mut() {
                if mapping.relationship.is_none() {
                    mapping.relationship = Some(Relationship::Primary);
                }
            }
        }
    }
}

// ─── N-002: Severity scalar expansion ────────────────────────────────────────

fn n002_severity_expansion(doc: &mut Document) {
    if let Some(ref severity) = doc.attack.severity {
        match severity {
            Severity::Scalar(level) => {
                doc.attack.severity = Some(Severity::Object {
                    level: level.clone(),
                    confidence: Some(50),
                });
            }
            Severity::Object { confidence: None, level } => {
                doc.attack.severity = Some(Severity::Object {
                    level: level.clone(),
                    confidence: Some(50),
                });
            }
            _ => {}
        }
    }
}

// ─── N-003: Auto-generate indicator IDs ──────────────────────────────────────

fn n003_auto_generate_indicator_ids(doc: &mut Document) {
    if let Some(indicators) = &mut doc.attack.indicators {
        for (i, ind) in indicators.iter_mut().enumerate() {
            if ind.id.is_none() {
                let id = if let Some(attack_id) = &doc.attack.id {
                    format!("{}-{:02}", attack_id, i + 1)
                } else {
                    format!("indicator-{:02}", i + 1)
                };
                ind.id = Some(id);
            }
        }
    }
}

// ─── N-004: Resolve pattern/semantic targets from surface registry ───────────

fn n004_resolve_targets(doc: &mut Document) {
    if let Some(indicators) = &mut doc.attack.indicators {
        for ind in indicators.iter_mut() {
            let surface_entry = lookup_surface(&ind.surface);

            if let Some(ref mut pattern) = ind.pattern {
                if pattern.target.is_none() {
                    if let Some(entry) = surface_entry {
                        pattern.target = Some(entry.default_target.to_string());
                    }
                }
            }

            if let Some(ref mut semantic) = ind.semantic {
                if semantic.target.is_none() {
                    if let Some(entry) = surface_entry {
                        semantic.target = Some(entry.default_target.to_string());
                    }
                }
            }
        }
    }
}

// ─── N-005: Expand pattern shorthand to standard form ────────────────────────

fn n005_expand_pattern_shorthand(doc: &mut Document) {
    if let Some(indicators) = &mut doc.attack.indicators {
        for ind in indicators.iter_mut() {
            if let Some(ref mut pattern) = ind.pattern {
                if pattern.is_shorthand() {
                    // Build a MatchCondition from the shorthand fields
                    let cond = MatchCondition {
                        contains: pattern.contains.take(),
                        starts_with: pattern.starts_with.take(),
                        ends_with: pattern.ends_with.take(),
                        regex: pattern.regex.take(),
                        any_of: pattern.any_of.take(),
                        gt: pattern.gt.take(),
                        lt: pattern.lt.take(),
                        gte: pattern.gte.take(),
                        lte: pattern.lte.take(),
                        exists: None,
                    };
                    pattern.condition = Some(Condition::Operators(cond));
                }
            }
        }
    }
}

// ─── N-006: Normalize single-phase form to multi-actor form ──────────────────

fn n006_single_phase_to_multi_actor(doc: &mut Document) {
    let exec = &doc.attack.execution;
    if exec.state.is_some() && exec.phases.is_none() && exec.actors.is_none() {
        let mode = exec.mode.clone().unwrap_or_default();
        let state = exec.state.clone();

        let phase = Phase {
            name: Some("phase-1".to_string()),
            description: None,
            mode: None,
            state,
            extractors: None,
            on_enter: None,
            trigger: None,
            extensions: std::collections::HashMap::new(),
        };

        let actor = Actor {
            name: "default".to_string(),
            mode: mode.clone(),
            phases: vec![phase],
            extensions: std::collections::HashMap::new(),
        };

        doc.attack.execution.actors = Some(vec![actor]);
        doc.attack.execution.state = None;
        doc.attack.execution.mode = None;
    }
}

// ─── N-007: Normalize multi-phase form to multi-actor form ───────────────────

fn n007_multi_phase_to_multi_actor(doc: &mut Document) {
    let exec = &doc.attack.execution;
    if exec.phases.is_some() && exec.actors.is_none() {
        let phases = exec.phases.clone().unwrap();
        let mode = exec
            .mode
            .clone()
            .or_else(|| {
                // Mode-less multi-phase: set actor.mode from phases[0].mode
                phases.first().and_then(|p| p.mode.clone())
            })
            .unwrap_or_default();

        let actor = Actor {
            name: "default".to_string(),
            mode,
            phases,
            extensions: std::collections::HashMap::new(),
        };

        doc.attack.execution.actors = Some(vec![actor]);
        doc.attack.execution.phases = None;
        doc.attack.execution.mode = None;
    }
}

// ─── N-008: Apply MCP tool field defaults ────────────────────────────────────

fn n008_mcp_tool_defaults(doc: &mut Document) {
    if let Some(actors) = &mut doc.attack.execution.actors {
        for actor in actors.iter_mut() {
            if actor.mode != "mcp_server" {
                continue;
            }

            for phase in &mut actor.phases {
                if let Some(ref mut state) = phase.state {
                    apply_mcp_tool_defaults(state);
                }
            }
        }
    }
}

fn apply_mcp_tool_defaults(state: &mut serde_json::Value) {
    if let Some(obj) = state.as_object_mut() {
        if let Some(tools) = obj.get_mut("tools") {
            if let Some(tools_arr) = tools.as_array_mut() {
                for tool in tools_arr.iter_mut() {
                    if let Some(tool_obj) = tool.as_object_mut() {
                        // inputSchema defaults to {"type": "object"}
                        if !tool_obj.contains_key("inputSchema") {
                            tool_obj.insert(
                                "inputSchema".to_string(),
                                serde_json::json!({"type": "object"}),
                            );
                        }
                        // description defaults to ""
                        if !tool_obj.contains_key("description") {
                            tool_obj.insert(
                                "description".to_string(),
                                serde_json::Value::String(String::new()),
                            );
                        }
                    }
                }
            }
        }
    }
}
