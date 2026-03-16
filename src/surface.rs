/// A surface registry entry mapping protocol operation name to protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceEntry {
    pub surface: &'static str,
    pub protocol: &'static str,
}

/// The v0.3 surface registry built from protocol operation names.
///
/// SDKs do not need a compile-time surface registry for target resolution (§2.21).
/// This registry is used only for V-018 warning validation.
pub static SURFACE_REGISTRY: &[SurfaceEntry] = &[
    // MCP operations
    SurfaceEntry {
        surface: "initialize",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "tools/list",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "tools/call",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "resources/list",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "resources/read",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "resources/subscribe",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "resources/unsubscribe",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "prompts/list",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "prompts/get",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "resources/templates/list",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "completion/complete",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "sampling/createMessage",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "elicitation/create",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "tasks/get",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "tasks/result",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "tasks/list",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "tasks/cancel",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "roots/list",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "ping",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/initialized",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/roots/list_changed",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/cancelled",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/tools/list_changed",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/resources/list_changed",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/resources/updated",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/prompts/list_changed",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/tasks/status",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/elicitation/complete",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/message",
        protocol: "mcp",
    },
    SurfaceEntry {
        surface: "notifications/progress",
        protocol: "mcp",
    },
    // A2A operations
    SurfaceEntry {
        surface: "message/send",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "message/stream",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "tasks/resubscribe",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "tasks/pushNotificationConfig/set",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "tasks/pushNotificationConfig/get",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "tasks/pushNotificationConfig/list",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "tasks/pushNotificationConfig/delete",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "agent/getAuthenticatedExtendedCard",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "agent_card/get",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "task/status",
        protocol: "a2a",
    },
    SurfaceEntry {
        surface: "task/artifact",
        protocol: "a2a",
    },
    // AG-UI operations
    SurfaceEntry {
        surface: "run_started",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "run_finished",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "run_error",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "step_started",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "step_finished",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "text_message_start",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "text_message_content",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "text_message_end",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "tool_call_start",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "tool_call_args",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "tool_call_end",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "tool_call_result",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "state_snapshot",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "state_delta",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "messages_snapshot",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "activity_snapshot",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "activity_delta",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "reasoning_start",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "reasoning_message_start",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "reasoning_message_content",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "reasoning_message_end",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "reasoning_message_chunk",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "reasoning_end",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "reasoning_encrypted_value",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "raw",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "custom",
        protocol: "ag_ui",
    },
    SurfaceEntry {
        surface: "run_agent_input",
        protocol: "ag_ui",
    },
];

/// Look up a surface entry by name.
pub fn lookup_surface(surface: &str) -> Option<&'static SurfaceEntry> {
    SURFACE_REGISTRY.iter().find(|e| e.surface == surface)
}

/// Known protocol identifiers.
pub static KNOWN_PROTOCOLS: &[&str] = &["mcp", "a2a", "ag_ui"];

/// Known mode strings.
pub static KNOWN_MODES: &[&str] = &[
    "mcp_server",
    "mcp_client",
    "a2a_server",
    "a2a_client",
    "ag_ui_client",
];
