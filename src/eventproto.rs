use serde::{Deserialize, Serialize};

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum EventType {
    HostPacket = 0
}

pub struct EventHeader {
    pub data_len: u32,
    pub event_type: EventType
}

impl EventHeader {
    pub fn size() -> usize {
        6
    }
    pub fn from_bytes(buf: &[u8; 6]) -> Result<Self,()> {
        let mut pbuf = [0u8; 4];
        pbuf.copy_from_slice(&buf[0..4]);
        let data_len = u32::from_be_bytes(pbuf);
        let mut pbuf = [0u8; 2];
        pbuf.copy_from_slice(&buf[4..6]);
        let event_type = u16::from_be_bytes(pbuf);
        const HOST_PACKET: u16 = EventType::HostPacket as u16;
        let event_type = match event_type {
            HOST_PACKET => EventType::HostPacket,
            _ => return Err(())
        };
        Ok(Self {
            data_len,
            event_type: EventType::HostPacket
        })
    }
    pub fn to_bytes(&self) -> [u8; 6] {
        let mut buf = [0u8; 6];
        buf[0..4].copy_from_slice(&(self.data_len).to_be_bytes());
        buf[4..6].copy_from_slice(&(self.event_type as u16).to_be_bytes());
        buf
    }
}