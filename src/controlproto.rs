use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Greeting {
    pub name: String,
    pub major: u16,
    pub minor: u16
}

#[repr(u32)]
pub enum Command {
    EXIT = 0
}
