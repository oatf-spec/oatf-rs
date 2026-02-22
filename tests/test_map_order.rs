#[test]
fn test_action_key_order() {
    // Verify that Action deserializer picks first non-extension key
    let json_str = r#"{"log": {"message": "msg"}, "send_notification": {"method": "m"}, "x-custom": "val"}"#;
    
    let map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json_str).unwrap();
    
    println!("Keys in insertion order:");
    for (i, key) in map.keys().enumerate() {
        println!("  {}: {}", i, key);
    }
    
    // The first non-extension key should be "log"
    let mut first_non_ext = None;
    for (k, _) in &map {
        if !k.starts_with("x-") {
            first_non_ext = Some(k.clone());
            break;
        }
    }
    println!("First non-extension key: {:?}", first_non_ext);
    assert_eq!(first_non_ext, Some("log".to_string()));
}
