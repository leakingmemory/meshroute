use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Greeting {
    pub name: String,
    pub major: u16,
    pub minor: u16
}

#[derive(Serialize, Deserialize)]
pub struct ListenCmd {
    pub listen: String
}

#[derive(Serialize, Deserialize)]
pub struct PairCmd {
    pub addr: String
}

#[repr(u32)]
pub enum Command {
    EXIT = 0,
    CAPTURE = 1,
    LISTEN = 2,
    PAIR = 3,
}

#[repr(u32)]
#[derive(Clone)]
pub enum ControlMsgType {
    HOST_PACKET = 0
}

pub struct ControlMsgHdr {
    pub len: u32,
    pub msg_type: ControlMsgType
}

impl ControlMsgHdr {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf: [u8; 8] = [0u8; 8];
        buf[0..4].copy_from_slice(&self.len.to_be_bytes());
        let tp = self.msg_type.clone();
        let tp = tp as u32;
        buf[4..8].copy_from_slice(&tp.to_be_bytes());
        buf
    }
    pub fn from_bytes(bytes: &[u8;8]) -> Result<Self, ()> {
        let mut pbuf: [u8; 4] = [0u8; 4];
        pbuf.copy_from_slice(&bytes[0..4]);
        let len = u32::from_be_bytes(pbuf);
        pbuf.copy_from_slice(&bytes[4..8]);
        let msg_type = u32::from_be_bytes(pbuf);
        const HOST_PACKET: u32 = ControlMsgType::HOST_PACKET as u32;
        let msg_type = match msg_type {
            HOST_PACKET => ControlMsgType::HOST_PACKET,
            _ => return Err(())
        };
        Ok(Self { len, msg_type })
    }
}