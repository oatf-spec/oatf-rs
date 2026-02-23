/// A surface registry entry mapping surface name to protocol and default target path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceEntry {
    pub surface: &'static str,
    pub protocol: &'static str,
    pub default_target: &'static str,
}

/// The v0.1 surface registry as a compile-time constant.
pub static SURFACE_REGISTRY: &[SurfaceEntry] = &[
    // MCP surfaces
    SurfaceEntry {
        surface: "tool_description",
        protocol: "mcp",
        default_target: "tools[*].description",
    },
    SurfaceEntry {
        surface: "tool_input_schema",
        protocol: "mcp",
        default_target: "tools[*].inputSchema",
    },
    SurfaceEntry {
        surface: "tool_name",
        protocol: "mcp",
        default_target: "tools[*].name",
    },
    SurfaceEntry {
        surface: "tool_annotations",
        protocol: "mcp",
        default_target: "tools[*].annotations",
    },
    SurfaceEntry {
        surface: "tool_output_schema",
        protocol: "mcp",
        default_target: "tools[*].outputSchema",
    },
    SurfaceEntry {
        surface: "tool_response",
        protocol: "mcp",
        default_target: "content[*]",
    },
    SurfaceEntry {
        surface: "tool_structured_response",
        protocol: "mcp",
        default_target: "structuredContent",
    },
    SurfaceEntry {
        surface: "tool_arguments",
        protocol: "mcp",
        default_target: "arguments",
    },
    SurfaceEntry {
        surface: "resource_content",
        protocol: "mcp",
        default_target: "contents[*]",
    },
    SurfaceEntry {
        surface: "resource_uri",
        protocol: "mcp",
        default_target: "resources[*].uri",
    },
    SurfaceEntry {
        surface: "resource_description",
        protocol: "mcp",
        default_target: "resources[*].description",
    },
    SurfaceEntry {
        surface: "prompt_content",
        protocol: "mcp",
        default_target: "messages[*].content",
    },
    SurfaceEntry {
        surface: "prompt_arguments",
        protocol: "mcp",
        default_target: "arguments",
    },
    SurfaceEntry {
        surface: "prompt_description",
        protocol: "mcp",
        default_target: "prompts[*].description",
    },
    SurfaceEntry {
        surface: "server_notification",
        protocol: "mcp",
        default_target: "params",
    },
    SurfaceEntry {
        surface: "server_capability",
        protocol: "mcp",
        default_target: "capabilities",
    },
    SurfaceEntry {
        surface: "server_info",
        protocol: "mcp",
        default_target: "serverInfo",
    },
    SurfaceEntry {
        surface: "sampling_request",
        protocol: "mcp",
        default_target: "params",
    },
    SurfaceEntry {
        surface: "elicitation_request",
        protocol: "mcp",
        default_target: "params",
    },
    SurfaceEntry {
        surface: "elicitation_response",
        protocol: "mcp",
        default_target: "result",
    },
    SurfaceEntry {
        surface: "mcp_task_status",
        protocol: "mcp",
        default_target: "task",
    },
    SurfaceEntry {
        surface: "mcp_task_result",
        protocol: "mcp",
        default_target: "result",
    },
    SurfaceEntry {
        surface: "roots_response",
        protocol: "mcp",
        default_target: "roots[*]",
    },
    // A2A surfaces
    SurfaceEntry {
        surface: "agent_card",
        protocol: "a2a",
        default_target: "",
    },
    SurfaceEntry {
        surface: "card_name",
        protocol: "a2a",
        default_target: "name",
    },
    SurfaceEntry {
        surface: "card_description",
        protocol: "a2a",
        default_target: "description",
    },
    SurfaceEntry {
        surface: "skill_description",
        protocol: "a2a",
        default_target: "skills[*].description",
    },
    SurfaceEntry {
        surface: "skill_name",
        protocol: "a2a",
        default_target: "skills[*].name",
    },
    SurfaceEntry {
        surface: "task_message",
        protocol: "a2a",
        default_target: "messages[*]",
    },
    SurfaceEntry {
        surface: "task_artifact",
        protocol: "a2a",
        default_target: "artifacts[*]",
    },
    SurfaceEntry {
        surface: "task_status",
        protocol: "a2a",
        default_target: "status.state",
    },
    // AG-UI surfaces
    SurfaceEntry {
        surface: "message_history",
        protocol: "ag_ui",
        default_target: "messages[*]",
    },
    SurfaceEntry {
        surface: "tool_definition",
        protocol: "ag_ui",
        default_target: "tools[*]",
    },
    SurfaceEntry {
        surface: "tool_result",
        protocol: "ag_ui",
        default_target: "messages[*]",
    },
    SurfaceEntry {
        surface: "agent_state",
        protocol: "ag_ui",
        default_target: "state",
    },
    SurfaceEntry {
        surface: "forwarded_props",
        protocol: "ag_ui",
        default_target: "forwardedProps",
    },
    SurfaceEntry {
        surface: "agent_event",
        protocol: "ag_ui",
        default_target: "data",
    },
    SurfaceEntry {
        surface: "agent_tool_call",
        protocol: "ag_ui",
        default_target: "data",
    },
];

/// Look up a surface entry by name.
pub fn lookup_surface(surface: &str) -> Option<&'static SurfaceEntry> {
    SURFACE_REGISTRY.iter().find(|e| e.surface == surface)
}

/// Known protocol identifiers for v0.1.
pub static KNOWN_PROTOCOLS: &[&str] = &["mcp", "a2a", "ag_ui"];

/// Known mode strings for v0.1.
pub static KNOWN_MODES: &[&str] = &[
    "mcp_server",
    "mcp_client",
    "a2a_server",
    "a2a_client",
    "ag_ui_client",
];
