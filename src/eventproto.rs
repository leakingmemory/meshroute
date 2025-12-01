use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Event {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub event_type: u32
}