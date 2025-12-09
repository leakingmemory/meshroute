use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: [u8; 2],
    pub payload: Vec<u8>
}

pub trait EthernetAddress {
    fn is_individual(&self) -> bool;
    fn is_multicast(&self) -> bool;
}

impl EthernetAddress for &[u8; 6] {
    fn is_individual(&self) -> bool {
        (self[0] & 1) == 0
    }
    fn is_multicast(&self) -> bool {
        (self[0] & 1) != 0
    }
}

impl EthernetFrame {
    pub fn new() -> EthernetFrame {
        EthernetFrame {
            dst_mac: [0u8; 6],
            src_mac: [0u8; 6],
            ethertype: [0u8; 2],
            payload: Vec::new()
        }
    }
    pub fn is_individual(&self) -> bool {
        (&self.dst_mac).is_individual()
    }
    pub fn is_multicast(&self) -> bool {
        (&self.dst_mac).is_multicast()
    }
}