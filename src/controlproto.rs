use serde::{Serialize, Deserialize};
use crate::config;

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

#[derive(Serialize, Deserialize)]
pub struct AcceptPairingCmd {
    pub key_hash: [u8; 32]
}

#[derive(Serialize, Deserialize)]
pub struct PairResult {
    pub master_pubkey_sha256: [u8; 32],
    pub name: String,
    pub remote_name: String
}

#[derive(Serialize, Deserialize)]
pub struct PairingRequestListItem {
    pub master_pubkey_sha256: [u8; 32],
    pub name: String,
    pub expires: i64
}

#[derive(Serialize, Deserialize)]
pub struct PairingRequestList {
    pub requests: Vec<PairingRequestListItem>
}

#[derive(Serialize, Deserialize)]
pub struct PairedList {
    pub endpoints: Vec<config::PairedEndpoint>
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub master_pubkey_sha256: Vec<u8>,
    pub node_pubkey_sha256: Vec<u8>,
    pub node_expiry: i64
}

#[repr(u32)]
pub enum Command {
    EXIT = 0,
    CAPTURE = 1,
    LISTEN = 2,
    PAIR = 3,
    LIST_PAIRING_REQUESTS = 4,
    ACCEPT_PAIRING = 5,
    LIST_PAIRED_ENDPOINTS = 6,
    INFO_REQUEST = 7
}

#[repr(u32)]
#[derive(Clone)]
pub enum ControlMsgType {
    HOST_PACKET = 0,
    PAIRING_RESPONSE = 1,
    GENERIC_ERROR = 2,
    PAIRING_REQUEST_LIST = 3,
    PAIRED_LIST = 4,
    INFO_RESPONSE = 5
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
        const PAIRING_RESPONSE: u32 = ControlMsgType::PAIRING_RESPONSE as u32;
        const GENERIC_ERROR: u32 = ControlMsgType::GENERIC_ERROR as u32;
        const PAIRING_REQUEST_LIST: u32 = ControlMsgType::PAIRING_REQUEST_LIST as u32;
        const PAIRED_LIST: u32 = ControlMsgType::PAIRED_LIST as u32;
        const INFO_RESPONSE: u32 = ControlMsgType::INFO_RESPONSE as u32;
        let msg_type = match msg_type {
            HOST_PACKET => ControlMsgType::HOST_PACKET,
            PAIRING_RESPONSE => ControlMsgType::PAIRING_RESPONSE,
            GENERIC_ERROR => ControlMsgType::GENERIC_ERROR,
            PAIRING_REQUEST_LIST => ControlMsgType::PAIRING_REQUEST_LIST,
            PAIRED_LIST => ControlMsgType::PAIRED_LIST,
            INFO_RESPONSE => ControlMsgType::INFO_RESPONSE,
            _ => return Err(())
        };
        Ok(Self { len, msg_type })
    }
}