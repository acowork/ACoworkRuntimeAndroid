#[test]
fn encode_session_config_runtime_realistic() {
    use acowork_core::mqtt_proto::{SessionConfig, LlmAvailability, DataEnvelope, data_envelope};
    
    // Use the EXACT strings runtime would produce:
    // from line 175 of 20260828_185424.log:
    // sid=20260828_164707_343828 title=启动时红色报警框一闪而过的问题排查
    // model_id=MiniMax-M3 provider_id=minimax-cn-coding-plan workspace_id=ws-091813bf4349
    let cfg_real = |avail: LlmAvailability| SessionConfig {
        agent_id: "com.acowork.senior-engineer".into(),
        session_id: "20260828_164707_343828".into(),
        title: "启动时红色报警框一闪而过的问题排查".into(),
        provider_id: "minimax-cn-coding-plan".into(),
        model_id: "MiniMax-M3".into(),
        account_id: "".into(),
        reasoning_effort: "".into(),
        temperature: 0.1,
        workspace_id: "ws-091813bf4349".into(),
        llm_availability: avail as i32,
        context_window: None,
    };
    
    let enc = |cfg| DataEnvelope { version: 1, payload: Some(data_envelope::Payload::SessionConfig(cfg)) };
    
    let b_unspec = prost::Message::encode_to_vec(&enc(cfg_real(LlmAvailability::Unspecified)));
    let b_configured = prost::Message::encode_to_vec(&enc(cfg_real(LlmAvailability::Configured)));
    let b_missing = prost::Message::encode_to_vec(&enc(cfg_real(LlmAvailability::Missing)));
    let b_zero = prost::Message::encode_to_vec(&enc(cfg_real(LlmAvailability::try_from(0).unwrap())));
    
    println!("Runtime-realistic Unspecified (0): {}", b_unspec.len());
    println!("Runtime-realistic Configured (2):  {}", b_configured.len());
    println!("Runtime-realistic Missing (3):     {}", b_missing.len());
    println!("from_i32(0) sanity:                {}", b_zero.len());
}
