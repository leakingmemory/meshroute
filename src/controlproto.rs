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
pub struct LinkCmd {
    pub name: String
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

#[derive(Serialize, Deserialize)]
pub struct LinksList {
    pub links: Vec<String>
}

#[repr(u32)]
pub enum Command {
    Exit = 0,
    Capture = 1,
    Listen = 2,
    Pair = 3,
    ListPairingRequests = 4,
    AcceptPairing = 5,
    ListPairedEndpoints = 6,
    InfoRequest = 7,
    ListLinks = 8,
    AddLink = 9,
    RemoveLink = 10
}

#[repr(u32)]
#[derive(Clone)]
pub enum ControlMsgType {
    HostPacket = 0,
    PairingResponse = 1,
    GenericError = 2,
    PairingRequestList = 3,
    PairedList = 4,
    InfoResponse = 5,
    LinksList = 6,
    GenericOk = 7
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
        const HOST_PACKET: u32 = ControlMsgType::HostPacket as u32;
        const PAIRING_RESPONSE: u32 = ControlMsgType::PairingResponse as u32;
        const GENERIC_ERROR: u32 = ControlMsgType::GenericError as u32;
        const PAIRING_REQUEST_LIST: u32 = ControlMsgType::PairingRequestList as u32;
        const PAIRED_LIST: u32 = ControlMsgType::PairedList as u32;
        const INFO_RESPONSE: u32 = ControlMsgType::InfoResponse as u32;
        const LINKS_LIST: u32 = ControlMsgType::LinksList as u32;
        const GENERIC_OK: u32 = ControlMsgType::GenericOk as u32;
        let msg_type = match msg_type {
            HOST_PACKET => ControlMsgType::HostPacket,
            PAIRING_RESPONSE => ControlMsgType::PairingResponse,
            GENERIC_ERROR => ControlMsgType::GenericError,
            PAIRING_REQUEST_LIST => ControlMsgType::PairingRequestList,
            PAIRED_LIST => ControlMsgType::PairedList,
            INFO_RESPONSE => ControlMsgType::InfoResponse,
            LINKS_LIST => ControlMsgType::LinksList,
            GENERIC_OK => ControlMsgType::GenericOk,
            _ => return Err(())
        };
        Ok(Self { len, msg_type })
    }
}