/// An entry in the event-mode validity registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventModeEntry {
    pub event: &'static str,
    pub valid_modes: &'static [&'static str],
}

/// The v0.1 Event-Mode Validity Registry as a compile-time constant.
/// Each event maps to the set of modes for which it is valid.
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
        event: "completion/complete",
        valid_modes: &["mcp_server"],
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
        valid_modes: &["mcp_server", "mcp_client", "a2a_server"],
    },
    EventModeEntry {
        event: "tasks/result",
        valid_modes: &["mcp_server", "mcp_client"],
    },
    EventModeEntry {
        event: "tasks/list",
        valid_modes: &["mcp_server"],
    },
    EventModeEntry {
        event: "tasks/cancel",
        valid_modes: &["mcp_server", "a2a_server"],
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
        valid_modes: &["a2a_server"],
    },
    EventModeEntry {
        event: "tasks/pushNotification/set",
        valid_modes: &["a2a_server"],
    },
    EventModeEntry {
        event: "tasks/pushNotification/get",
        valid_modes: &["a2a_server"],
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
        event: "tool_call_end",
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
        event: "interrupt",
        valid_modes: &["ag_ui_client"],
    },
    EventModeEntry {
        event: "custom",
        valid_modes: &["ag_ui_client"],
    },
];

/// Look up an event entry by its base event name (qualifier stripped).
pub fn lookup_event(event: &str) -> Option<&'static EventModeEntry> {
    EVENT_MODE_REGISTRY.iter().find(|e| e.event == event)
}

/// Check if an event is valid for a given mode.
/// Returns None if the event is not in the registry (unrecognized event).
pub fn is_event_valid_for_mode(event_base: &str, mode: &str) -> Option<bool> {
    lookup_event(event_base).map(|entry| entry.valid_modes.contains(&mode))
}

/// Strip qualifier from event string: "tools/call:calculator" -> "tools/call"
pub fn strip_event_qualifier(event: &str) -> &str {
    event.split(':').next().unwrap_or(event)
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
