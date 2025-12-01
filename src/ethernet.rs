
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: [u8; 2],
    pub payload: Vec<u8>
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
        (self.dst_mac[0] & 1) == 0
    }
    pub fn is_multicast(&self) -> bool {
        (self.dst_mac[0] & 1) != 0
    }
}