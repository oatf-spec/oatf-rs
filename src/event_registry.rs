/// An entry in the event-mode validity registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventModeEntry {
    pub event: &'static str,
    pub valid_modes: &'static [&'static str],
}

/// The v0.1 Event-Mode Validity Registry as a compile-time constant.
/// Each event maps to the set of modes for which it is valid.
/// Source: format specification §7 Event-Mode Validity Matrix.
pub static EVENT_MODE_REGISTRY: &[EventModeEntry] = &[
    // MCP events
    EventModeEntry {
        event: "initialize",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "tools/list",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "tools/call",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "resources/list",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "resources/read",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "resources/subscribe",
        valid_modes: &["mcp_server"],
    },
    EventModeEntry {
        event: "resources/unsubscribe",
        valid_modes: &["mcp_server"],
    },
    EventModeEntry {
        event: "prompts/list",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "prompts/get",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "resources/templates/list",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "completion/complete",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "sampling/createMessage",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "elicitation/create",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "tasks/get",
        valid_modes: &["mcp_server", "mcp_client", "a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "tasks/result",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "tasks/list",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "tasks/cancel",
        valid_modes: &["mcp_server", "mcp_client", "a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "roots/list",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "ping",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "notifications/initialized",
        valid_modes: &["mcp_server"],
    },
    EventModeEntry {
        event: "notifications/roots/list_changed",
        valid_modes: &["mcp_server"],
    },
    EventModeEntry {
        event: "notifications/cancelled",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "notifications/tools/list_changed",
        valid_modes: &["mcp_client"],
    },
    EventModeEntry {
        event: "notifications/resources/list_changed",
        valid_modes: &["mcp_client"],
    },
    EventModeEntry {
        event: "notifications/resources/updated",
        valid_modes: &["mcp_client"],
    },
    EventModeEntry {
        event: "notifications/prompts/list_changed",
        valid_modes: &["mcp_client"],
    },
    EventModeEntry {
        event: "notifications/tasks/status",
        valid_modes: &["mcp_client"],
    },
    EventModeEntry {
        event: "notifications/elicitation/complete",
        valid_modes: &["mcp_client"],
    },
    EventModeEntry {
        event: "notifications/message",
        valid_modes: &["mcp_client"],
    },
    EventModeEntry {
        event: "notifications/progress",
        valid_modes: &["mcp_client"],
    },
    // A2A events
    EventModeEntry {
        event: "message/send",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "message/stream",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "tasks/resubscribe",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "tasks/pushNotificationConfig/set",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "tasks/pushNotificationConfig/get",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "tasks/pushNotificationConfig/list",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "tasks/pushNotificationConfig/delete",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "agent/getAuthenticatedExtendedCard",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "agent_card/get",
        valid_modes: &["a2a_server", "a2a_client"],
    },
    EventModeEntry {
        event: "task/status",
        valid_modes: &["a2a_client"],
    },
    EventModeEntry {
        event: "task/artifact",
        valid_modes: &["a2a_client"],
    },
    // AG-UI events
    EventModeEntry {
        event: "run_started",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "run_finished",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "run_error",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "step_started",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "step_finished",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "text_message_start",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "text_message_content",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "text_message_end",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "tool_call_start",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "tool_call_args",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "tool_call_end",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "tool_call_result",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "state_snapshot",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "state_delta",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "messages_snapshot",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "activity_snapshot",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "activity_delta",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "reasoning_start",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "reasoning_message_start",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "reasoning_message_content",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "reasoning_message_end",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "reasoning_message_chunk",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "reasoning_end",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "reasoning_encrypted_value",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "raw",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "custom",
        valid_modes: &["ag_ui_client"],
    },
];

/// Look up an event entry by name.
pub fn lookup_event(event: &str) -> Option<&'static EventModeEntry> {
    EVENT_MODE_REGISTRY.iter().find(|e| e.event == event)
}

/// Check if an event is valid for a given mode.
/// Returns None if the event is not in the registry (unrecognized event).
pub fn is_event_valid_for_mode(event_base: &str, mode: &str) -> Option<bool> {
    lookup_event(event_base).map(|entry| entry.valid_modes.contains(&mode))
}

/// Extract the protocol component from a mode string.
/// "mcp_server" -> "mcp", "ag_ui_client" -> "ag_ui"
pub fn extract_protocol(mode: &str) -> &str {
    if let Some(stripped) = mode.strip_suffix("_server") {
        stripped
    } else if let Some(stripped) = mode.strip_suffix("_client") {
        stripped
    } else {
        mode
    }
}

/// Infer the single implicit protocol for the execution block.
///
/// Tries `execution.mode` first, then falls back to the single actor's mode
/// in multi-actor form.  Returns `None` when the protocol is ambiguous
/// (multiple actors with potentially different protocols).
pub fn infer_execution_protocol(execution: &crate::types::Execution) -> Option<String> {
    if let Some(mode) = &execution.mode {
        return Some(extract_protocol(mode).to_string());
    }
    execution.actors.as_ref().and_then(|actors| {
        if actors.len() == 1 {
            Some(extract_protocol(&actors[0].mode).to_string())
        } else {
            None
        }
    })
}
