use oatf::enums::AdvanceReason;
use oatf::primitives::evaluate_trigger;
use oatf::types::{ProtocolEvent, Trigger, TriggerResult, TriggerState};
use serde_json::json;
use std::time::Duration;

#[test]
fn evaluate_trigger_clamps_negative_count_to_one() {
    let trigger = Trigger {
        event: Some("tools/call".to_string()),
        count: Some(-5),
        match_predicate: None,
        after: None,
    };
    let event = ProtocolEvent {
        event_type: "tools/call".to_string(),
        content: json!({}),
    };
    let mut state = TriggerState::default();

    let result = evaluate_trigger(&trigger, Some(&event), Duration::from_secs(0), &mut state);

    match result {
        TriggerResult::Advanced { reason } => assert_eq!(reason, AdvanceReason::EventMatched),
        TriggerResult::NotAdvanced => panic!("negative count should be clamped to 1"),
    }
    assert_eq!(state.event_count, 1);
}

#[test]
fn evaluate_trigger_clamps_zero_count_to_one() {
    let trigger = Trigger {
        event: Some("tools/call".to_string()),
        count: Some(0),
        match_predicate: None,
        after: None,
    };
    let event = ProtocolEvent {
        event_type: "tools/call".to_string(),
        content: json!({}),
    };
    let mut state = TriggerState::default();

    let result = evaluate_trigger(&trigger, Some(&event), Duration::from_secs(0), &mut state);

    match result {
        TriggerResult::Advanced { reason } => assert_eq!(reason, AdvanceReason::EventMatched),
        TriggerResult::NotAdvanced => panic!("zero count should be clamped to 1"),
    }
    assert_eq!(state.event_count, 1);
}
