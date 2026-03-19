use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{pipe, PipeReader, PipeWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use bson::{deserialize_from_slice, serialize_to_vec};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::Signature;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Digest;
use crate::{config, controlproto, endpoint, ethernet, ethertable, eventproto, filedes, handshake, keyex, opts, serialwindow, uplink};
use crate::config::{PairedEndpoint, PairingRequest};
use crate::controlproto::Command;
use crate::controlproto::ControlMsgType::HostPacket;
use crate::endpoint::{EndpointMessage, PairingResponse};
use crate::ethernet::EthernetAddress;
use crate::ethertable::MacEntryLocation::LOCAL;
use crate::eventproto::EventType;
use crate::forkedworker::ForkedWorker;

fn read_control_object<T>(stream: &mut UnixStream) -> Result<T,()> where T: DeserializeOwned {
    let mut buf: Vec<u8> = Vec::new();
    {
        let len: u32;
        {
            let mut buf: [u8; 4] = [0u8; 4];
            let mut off = 0;
            while off < buf.len() {
                let rd = match stream.read(&mut buf[off..]) {
                    Ok(rd) => rd,
                    Err(_) => return Err(())
                };
                off += rd;
            }
            len = u32::from_be_bytes(buf);
        }
        buf.resize(len as usize, 0);
    }
    let mut off = 0;
    while off < buf.len() {
        let rd = match stream.read(&mut buf[off..]) {
            Ok(rd) => rd,
            Err(_) => return Err(())
        };
        off += rd;
    }
    match deserialize_from_slice(&buf) {
        Ok(obj) => Ok(obj),
        Err(_) => Err(())
    }
}

fn write_control(stream: &mut UnixStream, msg_type: controlproto::ControlMsgType) -> Result<(),()> {
    let buf = [0u8; 0];
    let hdr = controlproto::ControlMsgHdr {
        len: buf.len() as u32,
        msg_type
    };
    let hdr = hdr.to_bytes();
    let hdrlen = match stream.write(&hdr) {
        Ok(len) => len,
        Err(_) => {
            println!("Failed to write control message header");
            return Err(());
        }
    };
    if hdrlen != hdr.len() {
        println!("Failed to write control message header: short write");
        return Err(());
    }
    let msglen = match stream.write(buf.as_slice()) {
        Ok(len) => len,
        Err(_) => {
            println!("Failed to write control message data");
            return Err(());
        }
    };
    if msglen != buf.len() {
        println!("Failed to write control message data: short write");
        return Err(());
    }
    Ok(())
}

fn write_control_object<T>(stream: &mut UnixStream, msg_type: controlproto::ControlMsgType, obj: &T) -> Result<(),()> where T: Serialize {
    let buf = match serialize_to_vec(obj) {
        Ok(v) => v,
        Err(_) => {
            println!("Failed to serialize control message object");
            return Err(())
        }
    };
    let hdr = controlproto::ControlMsgHdr {
        len: buf.len() as u32,
        msg_type
    };
    let hdr = hdr.to_bytes();
    let hdrlen = match stream.write(&hdr) {
        Ok(len) => len,
        Err(_) => {
            println!("Failed to write control message header");
            return Err(());
        }
    };
    if hdrlen != hdr.len() {
        println!("Failed to write control message header: short write");
        return Err(());
    }
    let msglen = match stream.write(buf.as_slice()) {
        Ok(len) => len,
        Err(_) => {
            println!("Failed to write control message data");
            return Err(());
        }
    };
    if msglen != buf.len() {
        println!("Failed to write control message data: short write");
        return Err(());
    }
    match stream.flush() {
        Ok(_) => Ok(()),
        Err(_) => {
            println!("Failed to write control message data: flush failed");
            return Err(());
        }
    }
}

fn handle_control(config_file_name: &str, name: &str, mut stream: UnixStream, event_handler: Arc<Mutex<EventHandlerCtx>>, config: Arc<Mutex<config::Config>>, ctx: &WorkerContextThreadSafe) {
    let greeting = controlproto::Greeting {
        name: name.to_string(),
        major: 0,
        minor: 0
    };
    let msg = match serialize_to_vec(&greeting) {
        Ok(msg) => msg,
        Err(_) => {
            println!("Failed to serialize greeting for control protocol");
            return;
        }
    };
    let len = (msg.len() as u32).to_be_bytes();
    match stream.write(len.as_slice()) {
        Ok(_) => {},
        Err(_) => {
            println!("Failed to write length for control protocol");
            return;
        }
    }
    match stream.write(msg.as_slice()) {
        Ok(_) => {},
        Err(_) => {
            println!("Failed to write greeting for control protocol");
            return;
        }
    }
    loop {
        let mut cmdbuf = [0u8; 4];
        match stream.read_exact(&mut cmdbuf) {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to read cmd for control protocol");
                return;
            }
        }
        let cmd = u32::from_be_bytes(cmdbuf);
        const EXIT: u32 = Command::Exit as u32;
        const CAPTURE: u32 = Command::Capture as u32;
        const LISTEN: u32 = Command::Listen as u32;
        const PAIR: u32 = Command::Pair as u32;
        const LIST_PAIRING_REQUESTS: u32 = Command::ListPairingRequests as u32;
        const ACCEPT_PAIRING: u32 = Command::AcceptPairing as u32;
        const LIST_PAIRED_ENDPOINTS: u32 = Command::ListPairedEndpoints as u32;
        const INFO_REQUEST: u32 = Command::InfoRequest as u32;
        const LIST_LINKS: u32 = Command::ListLinks as u32;
        const ADD_LINK: u32 = Command::AddLink as u32;
        const REMOVE_LINK: u32 = Command::RemoveLink as u32;
        match cmd {
            EXIT => return,
            CAPTURE => {
                let mut event_handler = event_handler.lock().unwrap();
                event_handler.capture_streams.push(stream);
                return
            },
            LISTEN => {
                let listen_ctrl = match read_control_object::<controlproto::ListenCmd>(&mut stream) {
                    Ok(l) => l,
                    Err(_) => {
                        println!("Failed to read listen object");
                        return;
                    }
                };
                let mut config = config.lock().unwrap();
                if !listen_ctrl.listen.is_empty() {
                    println!("Changing listening setting from {} to {}", if let Some(ref listen) = config.listen { listen.as_str() } else { "None" }, listen_ctrl.listen.as_str());
                    config.listen = Some(listen_ctrl.listen);
                } else {
                    println!("Changing listening setting from {} to None", if let Some(ref listen) = config.listen { listen.as_str() } else { "None" });
                    config.listen = None;
                }
                match config.save(config_file_name) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to save new config");
                        return;
                    }
                }
                ctx.restart_me();
            },
            PAIR => {
                let pair_ctrl = match read_control_object::<controlproto::PairCmd>(&mut stream) {
                    Ok(l) => l,
                    Err(_) => {
                        println!("Failed to read pair object");
                        return;
                    }
                };
                let mut connection = match TcpStream::connect(pair_ctrl.addr.as_str()) {
                    Ok(c) => c,
                    Err(_) => {
                        println!("Failed to connect to {} for pairing.", pair_ctrl.addr);
                        match write_control(&mut stream, controlproto::ControlMsgType::GenericError) {
                            Ok(_) => {},
                            Err(_) => {
                                println!("Failed to write control response");
                                return;
                            }
                        };
                        return;
                    }
                };
                let endpoint_security = match handshake::run_client_handshake(&mut connection, &config) {
                    Ok(sec) => sec,
                    Err(_) => {
                        println!("Failed to shake hands with {} for pairing.", pair_ctrl.addr);
                        match write_control(&mut stream, controlproto::ControlMsgType::GenericError) {
                            Ok(_) => {},
                            Err(_) => {
                                println!("Failed to write control response");
                                return;
                            }
                        };
                        return;
                    }
                };
                let mut endpoint = endpoint::Endpoint::new(connection, endpoint_security);
                let pairing_request = endpoint::PairingRequest {
                    name: name.to_string()
                };
                let pairing_request = match serialize_to_vec(&pairing_request) {
                    Ok(p) => p,
                    Err(_) => {
                        println!("Failed to serialize pairing request");
                        return;
                    }
                };
                match endpoint.send(EndpointMessage::PairingRequest, pairing_request.as_slice()) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to send pairing request to {}", pair_ctrl.addr);
                        match write_control(&mut stream, controlproto::ControlMsgType::GenericError) {
                            Ok(_) => {},
                            Err(_) => {
                                println!("Failed to write control response");
                                return;
                            }
                        };
                        return;
                    }
                }
                let mut response_buf: Vec<u8> = Vec::new();
                let response = match endpoint.recv(&mut response_buf) {
                    Ok(r) => r,
                    Err(_) => {
                        println!("Failed to receive pairing response from {}", pair_ctrl.addr);
                        match write_control(&mut stream, controlproto::ControlMsgType::GenericError) {
                            Ok(_) => {},
                            Err(_) => {
                                println!("Failed to write control response");
                                return;
                            }
                        };
                        return;
                    }
                };
                match response {
                    EndpointMessage::PairingResponse => {
                        let pairing_response = match deserialize_from_slice::<PairingResponse>(response_buf.as_slice()) {
                            Ok(p) => p,
                            Err(_) => {
                                println!("Failed to deserialize pairing response");
                                return;
                            }
                        };
                        let mut master_pubkey_sha256 = [0u8; 32];
                        {
                            let mut config = config.lock().unwrap();
                            {
                                let digest = sha2::Sha256::digest(config.master_key.clone().unwrap().public_key.as_slice()).as_slice().to_vec();
                                for i in 0..digest.len() {
                                    master_pubkey_sha256[i] = digest[i];
                                }
                            }
                            config.pairing_requests.retain(|pairing_request| {
                                if pairing_request.expires < chrono::Utc::now().timestamp() {
                                    return false;
                                }
                                if pairing_request.master_pubkey_sha256.len() != endpoint.endpoint_security.master_pubkey_sha256.len() {
                                    return true;
                                }
                                for i in 0..endpoint.endpoint_security.master_pubkey_sha256.len() {
                                    if endpoint.endpoint_security.master_pubkey_sha256[i] != pairing_request.master_pubkey_sha256[i] {
                                        return true;
                                    }
                                }
                                false
                            });
                            config.pairing_requests.push(PairingRequest {
                                name: pair_ctrl.addr,
                                master_pubkey_sha256: endpoint.endpoint_security.master_pubkey_sha256.clone(),
                                expires: chrono::Utc::now().timestamp() + (5*24*60*60)
                            });
                            match config.save(config_file_name) {
                                Ok(_) => {},
                                Err(_) => {
                                    println!("Failed to save config with pairing request");
                                    return;
                                }
                            };
                        }
                        let pair_result = controlproto::PairResult {
                            master_pubkey_sha256,
                            name: name.to_string(),
                            remote_name: pairing_response.name
                        };
                        match write_control_object(&mut stream, controlproto::ControlMsgType::PairingResponse, &pair_result) {
                            Ok(_) => {},
                            Err(_) => {
                                println!("Failed to write control response");
                                return;
                            }
                        };
                        ctx.restart_me();
                        return;
                    },
                    _ => {
                        println!("Unexpected pairing response from {}", pair_ctrl.addr);
                        match write_control(&mut stream, controlproto::ControlMsgType::GenericError) {
                            Ok(_) => {},
                            Err(_) => {
                                println!("Failed to write control response");
                                return;
                            }
                        };
                        return;
                    }
                }
            },
            LIST_PAIRING_REQUESTS => {
                let mut pairing_requests: Vec<controlproto::PairingRequestListItem> = Vec::new();
                {
                    let config = config.lock().unwrap();
                    for pairing_request in &config.pairing_requests {
                        let mut master_pubkey_sha256 = [0u8; 32];
                        for i in 0..32 {
                            master_pubkey_sha256[i] = pairing_request.master_pubkey_sha256[i];
                        }
                        pairing_requests.push(controlproto::PairingRequestListItem {
                            master_pubkey_sha256,
                            name: pairing_request.name.clone(),
                            expires: pairing_request.expires
                        });
                    }
                }
                let pairing_requests = controlproto::PairingRequestList {
                    requests: pairing_requests
                };
                match write_control_object(&mut stream, controlproto::ControlMsgType::PairingRequestList, &pairing_requests) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to write control response");
                        return;
                    }
                };
            },
            LIST_PAIRED_ENDPOINTS => {
                let mut paired_endpoints: Vec<config::PairedEndpoint> = Vec::new();
                {
                    let config = config.lock().unwrap();
                    for paired_endpoint in &config.paired_endpoints {
                        paired_endpoints.push(config::PairedEndpoint {
                            master_pubkey_sha256: paired_endpoint.master_pubkey_sha256.clone(),
                            name: paired_endpoint.name.clone()
                        });
                    }
                }
                let paired_endpoints = controlproto::PairedList {
                    endpoints: paired_endpoints
                };
                match write_control_object(&mut stream, controlproto::ControlMsgType::PairedList, &paired_endpoints) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to write control response");
                        return;
                    }
                };
            },
            ACCEPT_PAIRING => {
                let remote_name;
                let accept_pairing_ctrl = match read_control_object::<controlproto::AcceptPairingCmd>(&mut stream) {
                    Ok(l) => l,
                    Err(_) => {
                        println!("Failed to read pair object");
                        return;
                    }
                };
                let mut master_pubkey_sha256 = [0u8; 32];
                {
                    let mut config = config.lock().unwrap();
                    {
                        let digest = sha2::Sha256::digest(config.master_key.clone().unwrap().public_key.as_slice()).as_slice().to_vec();
                        for i in 0..digest.len() {
                            master_pubkey_sha256[i] = digest[i];
                        }
                    }
                    let mut accept_pairing: Option<PairingRequest> = None;
                    config.pairing_requests.retain(|pairing_request| {
                        if pairing_request.expires < chrono::Utc::now().timestamp() {
                            return false;
                        }
                        if pairing_request.master_pubkey_sha256.len() != accept_pairing_ctrl.key_hash.len() {
                            return true;
                        }
                        for i in 0..accept_pairing_ctrl.key_hash.len() {
                            if accept_pairing_ctrl.key_hash[i] != pairing_request.master_pubkey_sha256[i] {
                                return true;
                            }
                        }
                        accept_pairing = Some(pairing_request.clone());
                        false
                    });
                    remote_name = if let Some(accept_pairing) = accept_pairing {
                        config.paired_endpoints.push(PairedEndpoint {
                            name: accept_pairing.name.clone(),
                            master_pubkey_sha256: accept_pairing_ctrl.key_hash.to_vec()
                        });
                        match config.save(config_file_name) {
                            Ok(_) => {},
                            Err(_) => {
                                println!("Failed to save config with pairing request");
                                return;
                            }
                        };
                        Some(accept_pairing.name)
                    } else {
                        None
                    }
                }
                if let Some(remote_name) = remote_name {
                    let pair_result = controlproto::PairResult {
                        master_pubkey_sha256,
                        name: name.to_string(),
                        remote_name
                    };
                    match write_control_object(&mut stream, controlproto::ControlMsgType::PairingResponse, &pair_result) {
                        Ok(_) => {},
                        Err(_) => {
                            println!("Failed to write control response");
                            return;
                        }
                    };
                    ctx.restart_me();
                }
            },
            INFO_REQUEST => {
                let master_pubkey_sha256;
                let node_pubkey_sha256;
                let mut node_expiry: i64 = 0;
                {
                    let config = config.lock().unwrap();
                    master_pubkey_sha256 = match &config.master_key {
                        Some(master_key) => {
                            sha2::Sha256::digest(master_key.public_key.as_slice()).as_slice().to_vec()
                        },
                        None => {
                            Vec::new()
                        }
                    };
                    node_pubkey_sha256 = match &config.node_key {
                        Some(node_key) => {
                            node_expiry = node_key.replace_after.timestamp();
                            sha2::Sha256::digest(node_key.key.public_key.as_slice()).as_slice().to_vec()
                        },
                        None => {
                            Vec::new()
                        }
                    };
                }
                let info = controlproto::InfoResponse {
                    master_pubkey_sha256,
                    node_pubkey_sha256,
                    node_expiry
                };
                match write_control_object(&mut stream, controlproto::ControlMsgType::InfoResponse, &info) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to write control response");
                        return;
                    }
                };
            },
            LIST_LINKS => {
                let mut links: Vec<String> = Vec::new();
                {
                    let config = config.lock().unwrap();
                    for link in &config.links {
                        links.push(link.clone());
                    }
                }
                let links_resp = controlproto::LinksList {
                    links
                };
                match write_control_object(&mut stream, controlproto::ControlMsgType::LinksList, &links_resp) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to write control response");
                        return;
                    }
                };
            },
            ADD_LINK => {
                let add_link = match read_control_object::<controlproto::LinkCmd>(&mut stream) {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Failed to read control object for request add-link");
                        return;
                    }
                };
                {
                    let mut config = config.lock().unwrap();
                    config.links.retain(|l| !l.eq_ignore_ascii_case(add_link.name.as_str()));
                    config.links.push(add_link.name);
                    match config.save(config_file_name) {
                        Ok(_) => {},
                        Err(_) => {
                            println!("Failed to save config");
                            return;
                        }
                    }
                }
                match write_control(&mut stream, controlproto::ControlMsgType::GenericOk) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to write control response");
                        return;
                    }
                };
                ctx.restart_me();
                return;
            },
            REMOVE_LINK => {
                let add_link = match read_control_object::<controlproto::LinkCmd>(&mut stream) {
                    Ok(a) => a,
                    Err(_) => {
                        println!("Failed to read control object for request add-link");
                        return;
                    }
                };
                {
                    let mut config = config.lock().unwrap();
                    config.links.retain(|l| !l.eq_ignore_ascii_case(add_link.name.as_str()));
                    match config.save(config_file_name) {
                        Ok(_) => {},
                        Err(_) => {
                            println!("Failed to save config");
                            return;
                        }
                    }
                }
                match write_control(&mut stream, controlproto::ControlMsgType::GenericOk) {
                    Ok(_) => {},
                    Err(_) => {
                        println!("Failed to write control response");
                        return;
                    }
                };
                ctx.restart_me();
                return;
            },
            _ => {
                println!("Unknown command: {}", cmd);
                return;
            }
        };
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
pub struct TunIfreq {
    pub ifr_name: [libc::c_char; libc::IFNAMSIZ],
    pub ifr_flags: libc::c_short,
    pub ifr_pad: [u8; 22]
}

pub struct EthernetHandlerCtx {
    pub frame: ethernet::EthernetFrame,
    pub event_writer: PipeWriter,
    pub mac_table: ethertable::MacTable,
    pub uplinks: Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>,
    pub uplink_mactables: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<ethertable::MacTable>>>>>,
    pub masterkey_hash: Vec<u8>,
    pub serial: Arc<AtomicU32>
}

impl EthernetHandlerCtx {
    pub fn new(event_writer: PipeWriter, uplinks: Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>, uplink_mactables: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<ethertable::MacTable>>>>>, masterkey_hash: Vec<u8>) -> Self {
        Self {
            frame: ethernet::EthernetFrame::new(),
            event_writer,
            mac_table: ethertable::MacTable::new(),
            uplinks,
            uplink_mactables,
            masterkey_hash,
            serial: Arc::new(AtomicU32::new(0))
        }
    }
}

pub fn handle_ethernet_frame(ctx: &mut EthernetHandlerCtx) -> Result<(),()> {
    if (&ctx.frame.src_mac).is_individual() {
        ctx.mac_table.borrow_entry(&ctx.frame.src_mac, |entry| {
            entry.location = LOCAL;
        });
    }
    let mut uplink_addr: Vec<u8> = Vec::new();
    {
        let uplink_mactables = ctx.uplink_mactables.lock().unwrap().clone();
        for (key, mactable) in uplink_mactables {
            let mut mactable = mactable.lock().unwrap();
            if (&ctx.frame.src_mac).is_individual() {
                mactable.remove_entry_if_exists(&ctx.frame.src_mac);
            }
            if uplink_addr.is_empty() && (&ctx.frame.dst_mac).is_individual() && mactable.has_entry(&ctx.frame.dst_mac) {
                uplink_addr = key;
            }
        }
    }
    match serialize_to_vec(&ctx.frame) {
        Ok(data) => {
            let hdr = eventproto::EventHeader {
                data_len: data.len() as u32,
                event_type: EventType::HostPacket
            };
            let hdr = hdr.to_bytes();
            match match ctx.event_writer.write_all(&hdr) {
                Ok(_) => ctx.event_writer.write_all(&data),
                Err(_) => return Err(())
            } {
                Ok(_) => {},
                Err(_) => return Err(())
            }
            {
                let serial = ctx.serial.fetch_add(1, Ordering::SeqCst) + 1;
                let fwd_packet: uplink::UplinkPacket = uplink::UplinkPacket {
                    source: ctx.masterkey_hash.clone(),
                    trail: Vec::new(),
                    destination: uplink_addr,
                    payload: data,
                    serial: serial
                };
                uplink::forward_packet(&fwd_packet, &ctx.uplinks);
            }
            Ok(())
        },
        Err(_) => {
            println!("Failed to serialize ethernet frame event");
            Err(())
        }
    }
}

pub fn handle_ethernet(ctx: &mut EthernetHandlerCtx, data: &[u8]) -> Result<(),()> {
    if data.len() < 18 {
        println!("Invalid ethernet frame: too short");
        return Ok(());
    }
    for i in 0..6 {
        ctx.frame.dst_mac[i] = data[i];
    }
    for i in 6..12 {
        ctx.frame.src_mac[i-6] = data[i];
    }
    for i in 12..14 {
        ctx.frame.ethertype[i-12] = data[i];
    }
    ctx.frame.payload.resize(data.len()-14, 0);
    for i in 14..data.len() {
        ctx.frame.payload[i-14] = data[i];
    }
    handle_ethernet_frame(ctx)
}

pub struct EventHandlerCtx {
    pub capture_streams: Vec<UnixStream>
}

impl EventHandlerCtx {
    pub fn new() -> Self {
        Self {
            capture_streams: Vec::new()
        }
    }
}

pub fn event_handler(mut event_reader: PipeReader, ctx: Arc<Mutex<EventHandlerCtx>>) {
    let mut event_buf: Vec<u8> = Vec::new();
    loop {
        let hdr;
        {
            let mut hdrbuf = [0u8; 6];
            let mut hdroff = 0;
            loop {
                match event_reader.read(&mut hdrbuf[hdroff..]) {
                    Ok(len) => { hdroff += len; },
                    Err(_) => {
                        println!("Failed to read event header");
                    }
                }
                if hdroff >= 6 { break; }
            }
            hdr = match eventproto::EventHeader::from_bytes(&hdrbuf) {
                Ok(hdr) => hdr,
                Err(_) => {
                    println!("Failed to deserialize event header");
                    return;
                }
            };
        }
        event_buf.resize(hdr.data_len as usize, 0);
        {
            let mut dataoff = 0;
            loop {
                match event_reader.read(&mut event_buf[dataoff..]) {
                    Ok(len) => { dataoff += len; },
                    Err(_) => {
                        println!("Failed to read event data");
                        return;
                    }
                }
                if dataoff >= hdr.data_len as usize { break; }
            }
        }
        let mut ctx = ctx.lock().unwrap();
        match hdr.event_type {
            EventType::HostPacket => {
                let frame: ethernet::EthernetFrame = match deserialize_from_slice(event_buf.as_slice()) {
                    Ok(p) => p,
                    Err(_) => {
                        println!("Failed to deserialize host packet event");
                        return;
                    }
                };
                println!(">> [{}] {:x?} -> {:x?} {:x?} {}", if frame.is_multicast() { "multi" } else { "single" }, frame.src_mac, frame.dst_mac, frame.ethertype, frame.payload.len());
                if !ctx.capture_streams.is_empty() {
                    let hdr = controlproto::ControlMsgHdr {
                        len: event_buf.len() as u32,
                        msg_type: HostPacket
                    };
                    let hdr = hdr.to_bytes();
                    ctx.capture_streams.retain_mut(|stream| {
                        let hdrlen = match stream.write(&hdr) {
                            Ok(len) => len,
                            Err(_) => {
                                println!("Failed to write control message header");
                                return false;
                            }
                        };
                        if hdrlen != hdr.len() {
                            println!("Failed to write control message header: short write");
                            return false;
                        }
                        let msglen = match stream.write(event_buf.as_slice()) {
                            Ok(len) => len,
                            Err(_) => {
                                println!("Failed to write control message data");
                                return false;
                            }
                        };
                        if msglen != event_buf.len() {
                            println!("Failed to write control message data: short write");
                            return false;
                        }
                        true
                    });
                }
            }
        }
    }
}

struct WorkerContext {
    pub name: String,
    pub config: Arc<Mutex<config::Config>>,
    pub config_filename: String,
    pub event_writer: PipeWriter,
    pub tap_dev: filedes::FileDes,
    pub restart_me_writer: PipeWriter
}

impl Clone for WorkerContext {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            config: self.config.clone(),
            config_filename: self.config_filename.clone(),
            event_writer: self.event_writer.try_clone().unwrap(),
            tap_dev: self.tap_dev.clone(),
            restart_me_writer: self.restart_me_writer.try_clone().unwrap()
        }
    }
}

impl WorkerContext {
    pub fn run_worker(&mut self) -> libc::c_int {
        let uplinks: Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>> = Arc::new(Mutex::new(Vec::new()));
        let uplink_mac_tables: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<ethertable::MacTable>>>>> = Arc::new(Mutex::new(HashMap::new()));
        let uplink_serial_window: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<serialwindow::SerialWindow<u32,128>>>>>> = Arc::new(Mutex::new(HashMap::new()));
        let listen_addr;
        let masterkey_hash;
        {
            let masterkey_pub;
            {
                let config = self.config.lock().unwrap();
                listen_addr = config.listen.clone();
                let master_key = &config.master_key;
                let public_key = if let Some(master_key) = master_key {
                    Some(master_key.public_key.clone())
                } else {
                    None
                };
                masterkey_pub = public_key.unwrap();
            }
            masterkey_hash = sha2::Sha256::digest(masterkey_pub.as_slice()).as_slice().to_vec();
        }
        println!("Network worker process initializing");
        let mut handlerctx = EthernetHandlerCtx::new(match self.event_writer.try_clone() {
            Ok(pw) => pw,
            Err(_) => {
                println!("Failed to clone event writer");
                return 1;
            }
        }, uplinks.clone(), uplink_mac_tables.clone(), masterkey_hash.clone());
        let tap_dev = Arc::new(Mutex::new(self.tap_dev.clone()));
        if let Some(listen_addr) = listen_addr {
            println!("Listening on tcp {}", listen_addr);
            let listen_socket = match TcpListener::bind(listen_addr.as_str()) {
                Ok(s) => Some(s),
                Err(_) => {
                    println!("Failed to start listening socket {}", listen_addr);
                    None
                }
            };
            if let Some(listen_socket) = listen_socket {
                let config = self.config.clone();
                let tap_dev = tap_dev.clone();
                let masterkey_hash = masterkey_hash.clone();
                let uplinks = uplinks.clone();
                let uplink_mac_tables = uplink_mac_tables.clone();
                let uplink_serial_window = uplink_serial_window.clone();
                let serial = handlerctx.serial.clone();
                let self_name = self.name.clone();
                let config_filename = self.config_filename.clone();
                let restart_me_writer = self.restart_me_writer.try_clone().unwrap();
                let _network_listener = thread::spawn(move || {
                    let mut client_threads: Vec<thread::JoinHandle<()>> = Vec::new();
                    for connection in listen_socket.incoming() {
                        let mut connection = match connection {
                            Ok(c) => c,
                            Err(_) => {
                                println!("Handling connection listening failed");
                                break;
                            }
                        };
                        let config = config.clone();
                        let tap_dev = tap_dev.clone();
                        let masterkey_hash = masterkey_hash.clone();
                        let uplinks = uplinks.clone();
                        let uplink_mac_tables = uplink_mac_tables.clone();
                        let uplink_serial_window = uplink_serial_window.clone();
                        let serial = serial.clone();
                        client_threads.retain(move |thread| {
                            !thread.is_finished()
                        });
                        let self_name = self_name.clone();
                        let config_filename = config_filename.clone();
                        let mut restart_me_writer = restart_me_writer.try_clone().unwrap();
                        let network_handler = thread::spawn(move || {
                            let endpoint_security = match handshake::run_server_handshake(&mut connection, &config) {
                                Ok(sec) => sec,
                                Err(_) => return
                            };
                            let mut endpoint = endpoint::Endpoint::new(connection, endpoint_security);
                            // TODO - should at least have timeouts to avoid denial of service
                            let mut req_vec: Vec<u8> = Vec::new();
                            loop {
                                let req_type = match endpoint.recv(&mut req_vec) {
                                    Ok(req_type) => req_type,
                                    Err(_) => return
                                };
                                {
                                    let config = config.lock().unwrap();
                                    for paired in &config.paired_endpoints {
                                        let mut matching = paired.master_pubkey_sha256.len() == endpoint.endpoint_security.master_pubkey_sha256.len();
                                        if matching {
                                            for i in 0..endpoint.endpoint_security.master_pubkey_sha256.len() {
                                                if endpoint.endpoint_security.master_pubkey_sha256[i] != paired.master_pubkey_sha256[i] {
                                                    matching = false;
                                                    break;
                                                }
                                            }
                                        }
                                        if matching {
                                            endpoint.name = Some(paired.name.clone());
                                        }
                                    }
                                }
                                match req_type {
                                    EndpointMessage::PairingRequest => {
                                        let pairing_request = match deserialize_from_slice::<endpoint::PairingRequest>(&req_vec) {
                                            Ok(r) => r,
                                            Err(_) => {
                                                println!("Failed to deserialize pairing request");
                                                return;
                                            }
                                        };
                                        {
                                            let mut config = config.lock().unwrap();
                                            config.pairing_requests.retain(|pairing_request| {
                                                if pairing_request.expires < chrono::Utc::now().timestamp() {
                                                    return false;
                                                }
                                                if pairing_request.master_pubkey_sha256.len() != endpoint.endpoint_security.master_pubkey_sha256.len() {
                                                    return true;
                                                }
                                                for i in 0..endpoint.endpoint_security.master_pubkey_sha256.len() {
                                                    if endpoint.endpoint_security.master_pubkey_sha256[i] != pairing_request.master_pubkey_sha256[i] {
                                                        return true;
                                                    }
                                                }
                                                false
                                            });
                                            config.pairing_requests.push(PairingRequest {
                                                name: pairing_request.name,
                                                master_pubkey_sha256: endpoint.endpoint_security.master_pubkey_sha256.clone(),
                                                expires: chrono::Utc::now().timestamp() + (5 * 24 * 60 * 60)
                                            });
                                            match config.save(config_filename.as_str()) {
                                                Ok(_) => {},
                                                Err(_) => {
                                                    println!("Failed to save config with pairing request");
                                                    return;
                                                }
                                            };
                                        }
                                        let pairing_result = endpoint::PairingResponse {
                                            name: self_name.clone()
                                        };
                                        let pairing_result = match serialize_to_vec(&pairing_result) {
                                            Ok(p) => p,
                                            Err(_) => {
                                                println!("Failed to serialize pairing response");
                                                return;
                                            }
                                        };
                                        match endpoint.send(EndpointMessage::PairingResponse, pairing_result.as_slice()) {
                                            Ok(_) => {},
                                            Err(_) => {
                                                println!("Failed to send pairing response");
                                                return;
                                            }
                                        }
                                        println!("Stopping network worker process and equesting restart");
                                        let buf = [1u8];
                                        match restart_me_writer.write(&buf) {
                                            Ok(_) => {},
                                            Err(_) => {
                                                println!("Failed to write to restart pipe");
                                            }
                                        }
                                        std::process::exit(0);
                                    }
                                    EndpointMessage::Uplink => {
                                        if let Some(endpoint_name) = &endpoint.name {
                                            let endpoint_name = endpoint_name.clone();
                                            println!("Uplink accepted for {}", endpoint_name);
                                            uplink::run_uplink(tap_dev, masterkey_hash, uplinks, uplink_mac_tables, uplink_serial_window, &mut endpoint, serial);
                                            println!("Uplink closed for {}", endpoint_name);
                                        } else {
                                            println!("Uplink rejected");
                                            endpoint.send(EndpointMessage::GenericError, b"").unwrap();
                                        }
                                        break;
                                    },
                                    EndpointMessage::PairingResponse => {
                                        println!("Unexpected pairing response received");
                                        break;
                                    }
                                    EndpointMessage::GenericError => {
                                        println!("Endpoint {} returned generic error", match &endpoint.name {
                                            Some(name) => name.as_str(),
                                            None => "unknown"
                                        });
                                        break;
                                    }
                                }
                            }
                        });
                        client_threads.push(network_handler);
                    }
                });
            }
        } else {
            println!("No listening socket configured");
        }
        let links_from_config;
        {
            let config = self.config.lock().unwrap();
            links_from_config = config.links.clone();
        }
        for link_from_config in links_from_config {
            let config = self.config.clone();
            let tap_dev = tap_dev.clone();
            let masterkey_hash = masterkey_hash.clone();
            let uplinks = uplinks.clone();
            let uplink_mac_tables = uplink_mac_tables.clone();
            let uplink_serial_window = uplink_serial_window.clone();
            let serial = handlerctx.serial.clone();
            thread::spawn(move || {
                let config = config;
                let uplinks = uplinks;
                let uplink_mac_tables = uplink_mac_tables;
                loop {
                    println!("Opening connection {}", link_from_config);
                    let mut connection = match TcpStream::connect(link_from_config.as_str()) {
                        Ok(c) => c,
                        Err(_) => {
                            println!("Failed to connect to {}", link_from_config);
                            thread::sleep(Duration::from_secs(1));
                            println!("Reconnecting after 10 seconds..");
                            thread::sleep(Duration::from_secs(9));
                            continue;
                        }
                    };
                    let endpoint_security = match handshake::run_client_handshake(&mut connection, &config) {
                        Ok(sec) => sec,
                        Err(_) => {
                            println!("Handshake failed with {}", link_from_config);
                            thread::sleep(Duration::from_secs(1));
                            println!("Reconnecting after 10 seconds..");
                            thread::sleep(Duration::from_secs(9));
                            continue;
                        }
                    };
                    let mut endpoint = endpoint::Endpoint::new(connection, endpoint_security);
                    match endpoint.send(EndpointMessage::Uplink, b"") {
                        Ok(_) => {},
                        Err(_) => {
                            println!("Failed to send uplink message to {}", link_from_config);
                            thread::sleep(Duration::from_secs(1));
                            println!("Reconnecting after 10 seconds..");
                            thread::sleep(Duration::from_secs(9));
                            continue;
                        }
                    };
                    uplink::run_uplink(tap_dev.clone(), masterkey_hash.clone(), uplinks.clone(), uplink_mac_tables.clone(), uplink_serial_window.clone(), &mut endpoint, serial.clone());
                    println!("Lost connection {}", link_from_config);
                    thread::sleep(Duration::from_secs(1));
                    println!("Reconnecting after 10 seconds..");
                    thread::sleep(Duration::from_secs(9));
                }
            });
        }
        let mut pktbuf: Vec<u8> = Vec::new();
        loop {
            pktbuf.resize(65536, 0);
            {
                let size = match self.tap_dev.read(pktbuf.as_mut_slice()) {
                    Ok(size) => size,
                    Err(_) => {
                        println!("Failed to read from tap device");
                        return 1;
                    }
                };
                pktbuf.truncate(size);
            }
            match handle_ethernet(&mut handlerctx, pktbuf.as_slice()) {
                Ok(_) => {},
                Err(_) => {
                    println!("Failed to handle ethernet frame");
                    return 1;
                }
            }
        }
    }
}

#[derive(Clone)]
struct WorkerContextThreadSafe {
    pub restart_me_writer: Arc<Mutex<PipeWriter>>,
    pub forkedworker: Arc<Mutex<Option<ForkedWorker>>>,
    pub ctx: Arc<Mutex<WorkerContext>>
}

impl WorkerContextThreadSafe {
    pub fn run_worker_process(&self) {
        let mut ctx;
        {
            let lctx = self.ctx.lock().unwrap();
            ctx = lctx.clone();
        }
        let mut forkedworker = self.forkedworker.lock().unwrap().take();
        if let Some(_forkedworker) = forkedworker.take() {
            println!("Stopping network worker process");
        }
        println!("Starting network worker process");
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("Failed to fork worker process");
            return;
        } else if pid == 0  {
            println!("Spawned as child process");
            ctx.run_worker();
            std::process::exit(0);
        }
        println!("Network worker process spawned {}", pid);
        let forkedworker = ForkedWorker::new_from_pid(pid);
        let mut fw = self.forkedworker.lock().unwrap();
        if fw.is_none()  {
            fw.replace(forkedworker);
        } else {
            println!("Stopping worker due to simultaneous start");
        }
        println!("Network worker process spawned");
    }
    pub fn restart_me(&self) {
        let mut forkedworker = self.forkedworker.lock().unwrap().take();
        if let Some(_forkedworker) = forkedworker.take() {
            println!("Stopping network worker process");
        }
        println!("Requesting restart");
        let buf = [1u8];
        match self.restart_me_writer.lock().unwrap().write(&buf) {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to write to restart pipe");
            }
        }
        std::process::exit(0);
    }
}

pub fn run_daemon(opts: &opts::Opts, name: &str) -> ExitCode {
    loop {
        let mut restart_me_reader;
        let mut restart_me_writer;
        (restart_me_reader, restart_me_writer) = match pipe() {
            Ok(endpoints) => endpoints,
            Err(_) => {
                println!("Failed to create pipe for event channel");
                return ExitCode::from(1);
            }
        };
        let pid = unsafe { libc::fork() };
        if pid < 0  {
            println!("Failed to fork daemon process");
            return run_daemon_w(&mut restart_me_writer, opts, name)
        } else if pid == 0  {
            println!("Spawned as child process");
            return run_daemon_w(&mut restart_me_writer, opts, name);
        } else {
            let mut buf = [0u8; 1];
            let rd = match restart_me_reader.read(&mut buf) {
                Ok(s) => s,
                Err(_) => {
                    println!("Failed to read from restart pipe");
                    unsafe { libc::kill(pid, libc::SIGTERM); }
                    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
                    return ExitCode::from(1);
                }
            };
            if rd == 0  {
                println!("No restart requested");
                unsafe { libc::kill(pid, libc::SIGTERM); }
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
                return ExitCode::from(0);
            }
            unsafe { libc::kill(pid, libc::SIGTERM); }
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0); }
            thread::sleep(Duration::from_secs(1));
        }
    }
}

pub fn run_daemon_w(restart_me_writer: &mut PipeWriter, opts: &opts::Opts, name: &str) -> ExitCode {
    let mut config_file_name = opts.config_dir.clone();
    if !config_file_name.ends_with('/') {
        config_file_name.push('/');
    }
    config_file_name.insert_str(config_file_name.len(), name);
    config_file_name.insert_str(config_file_name.len(), ".config");
    let mut socket_file_name = opts.socket_dir.clone();
    if !socket_file_name.ends_with('/') {
        socket_file_name.push('/');
    }
    socket_file_name.insert_str(socket_file_name.len(), name);
    let mut lock_file_name = socket_file_name.clone();
    socket_file_name.insert_str(socket_file_name.len(), ".socket");
    lock_file_name.insert_str(lock_file_name.len(), ".lock");
    println!("config file: {}", config_file_name);
    println!("socket file: {}", socket_file_name);
    println!("lock file: {}", lock_file_name);
    let socket_dir = std::path::Path::new(&lock_file_name).parent().unwrap();
    if !socket_dir.exists() {
        if let Err(_) = std::fs::create_dir_all(socket_dir) {
            println!("failed to create directory for socket and lock files: {}", socket_dir.display());
            return ExitCode::from(1);
        }
    }
    let file = match std::fs::File::create(lock_file_name.clone()) {
        Ok(f) => f,
        Err(_) => {
            println!("failed to open or create lock file: {}", lock_file_name);
            return ExitCode::from(1);
        }
    };
    match file.try_lock() {
        Ok(_) => {},
        Err(_) => {
            println!("failed to lock lock file: {}", lock_file_name);
            return ExitCode::from(1);
        }
    }
    let config = Arc::new(Mutex::new(match config::Config::from_file(config_file_name.as_str()) {
        Ok(config) => config,
        Err(_) => return ExitCode::from(1)
    }));
    {
        let mut config = config.lock().unwrap();
        if config.master_key.is_none() {
            println!("Generating master key for this node");
            let mut rnd = rsa::rand_core::OsRng;
            let bits = 4096;
            let priv_key = match RsaPrivateKey::new(&mut rnd, bits) {
                Ok(k) => k,
                Err(_) => {
                    println!("Failed to generate master key");
                    return ExitCode::from(1);
                }
            };
            let pub_key = RsaPublicKey::from(&priv_key);
            let priv_key_der = match priv_key.to_pkcs8_der() {
                Ok(d) => d,
                Err(_) => {
                    println!("Failed to serialize master key as der");
                    return ExitCode::from(1);
                }
            };
            let pub_key_der = match pub_key.to_pkcs1_der() {
                Ok(d) => d,
                Err(_) => {
                    println!("Failed to serialize master key (public part) as der");
                    return ExitCode::from(1);
                }
            };
            let priv_key_bytes = priv_key_der.as_bytes();
            let pub_key_bytes = pub_key_der.as_bytes();
            config.master_key = Some(keyex::RsaKeyPair {
                private_key: priv_key_bytes.to_vec(),
                public_key: pub_key_bytes.to_vec()
            });
            match config.save(config_file_name.as_str()) {
                Ok(_) => {},
                Err(_) => {
                    println!("Failed to save config with new master key");
                    return ExitCode::from(1);
                }
            };
        }
        if let Some(ref nodekey) = config.node_key {
            let now = chrono::Local::now().to_utc();
            if now > nodekey.replace_after {
                println!("Node key is expired, discarding");
                config.node_key = None;
            }
        }
        if let Some(ref nodekey) = config.node_key {
            println!("Verifying the current node key");
            let public_key = match RsaPublicKey::from_pkcs1_der(match config.master_key {
                Some(ref master_key) => master_key,
                None => {
                    println!("Failed to load master key. Cannot verify node key.");
                    return ExitCode::from(1);
                }
            }.public_key.as_slice()) {
                Ok(k) => Some(k),
                Err(_) => {
                    println!("Failed to deserialize node public key. Clearing node key.");
                    None
                }
            };
            let signature = match Signature::try_from(nodekey.signature.as_slice()) {
                Ok(s) => Some(s),
                Err(_) => {
                    println!("Failed to deserialize node signature. Clearing node key.");
                    None
                }
            };
            if let Some(public_key) = public_key &&
                let Some(signature) = signature {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new_unprefixed(public_key);
                match verifying_key.verify(nodekey.key.public_key.as_slice(), &signature) {
                    Ok(()) => println!("Node key is valid"),
                    Err(e) => {
                        println!("Signature verification failed: {:?}. Clearing current node key.", e);
                        config.node_key = None;
                    },
                }
            } else {
                config.node_key = None;
            }
        }
        if config.node_key.is_none() {
            let pub_key;
            let nodekey;
            {
                println!("Generating a new node key");
                let mut rnd = rsa::rand_core::OsRng;
                let bits = 3072;
                let priv_key = match RsaPrivateKey::new(&mut rnd, bits) {
                    Ok(k) => k,
                    Err(_) => {
                        println!("Failed to generate master key");
                        return ExitCode::from(1);
                    }
                };
                pub_key = RsaPublicKey::from(&priv_key);
                let priv_key_der = match priv_key.to_pkcs8_der() {
                    Ok(d) => d,
                    Err(_) => {
                        println!("Failed to serialize master key as der");
                        return ExitCode::from(1);
                    }
                };
                let pub_key_der = match pub_key.to_pkcs1_der() {
                    Ok(d) => d,
                    Err(_) => {
                        println!("Failed to serialize master key (public part) as der");
                        return ExitCode::from(1);
                    }
                };
                let priv_key_bytes = priv_key_der.as_bytes();
                let pub_key_bytes = pub_key_der.as_bytes();
                nodekey = keyex::RsaKeyPair {
                    private_key: priv_key_bytes.to_vec(),
                    public_key: pub_key_bytes.to_vec()
                };
            }
            let priv_key = RsaPrivateKey::from_pkcs8_der(match config.master_key {
                Some(ref master_key) => master_key,
                None => {
                    println!("Failed to load master key. Cannot generate node key.");
                    return ExitCode::from(1);
                }
            }.private_key.as_slice()).unwrap();
            let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new_unprefixed(priv_key);
            let signature = signing_key.sign(nodekey.public_key.as_slice());
            config.node_key = Some(keyex::NodeKey {
                key: nodekey,
                replace_after: chrono::Local::now().to_utc() + chrono::Duration::days(365),
                signature: signature.to_vec()
            });
            match config.save(config_file_name.as_str()) {
                Ok(_) => {},
                Err(_) => {
                    println!("Failed to save config with new master key");
                    return ExitCode::from(1);
                }
            };
        }
    }
    println!("Keys are ready");
    match std::fs::remove_file(socket_file_name.clone()) {
        Ok(_) => {},
        Err(_) => {}
    };
    let control_listener = match UnixListener::bind(socket_file_name.clone()) {
        Ok(l) => l,
        Err(_) => {
            println!("failed to bind control socket: {}", socket_file_name);
            return ExitCode::from(1);
        }
    };
    let tap_dev = filedes::FileDes::open("/dev/net/tun", libc::O_RDWR, 0644);
    let mut ifreq: TunIfreq = TunIfreq {
        ifr_name: [0 as libc::c_char; 16],
        ifr_flags: (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short,
        ifr_pad: [0u8; 22]
    };
    if name.len() < 16 {
        for i in 0..name.len() {
            ifreq.ifr_name[i] = name.as_bytes()[i] as libc::c_char;
        }
    } else {
        for i in 0..16 {
            ifreq.ifr_name[i] = name.as_bytes()[i] as libc::c_char;
        }
    }
    match unsafe { tap_dev.ioctl(libc::TUNSETIFF, &ifreq as *const TunIfreq) } {
        Ok(_) => {}
        Err(_) => {
            println!("Failed to configure ethernet device: {}", name);
            return ExitCode::from(1);
        }
    }
    println!("Configured ethernet device {}", unsafe { CStr::from_ptr(ifreq.ifr_name.as_ptr() as *const libc::c_char) }.to_str().unwrap());
    let eventworker_ctx = Arc::new(Mutex::new(EventHandlerCtx::new()));
    let _eventworker_thread;
    let ctx: WorkerContextThreadSafe;
    {
        let event_reader;
        {
            let event_writer;
            (event_reader, event_writer) = match pipe() {
                Ok(endpoints) => endpoints,
                Err(_) => {
                    println!("Failed to create pipe for event channel");
                    return ExitCode::from(1);
                }
            };
            let forkedworker: Option<ForkedWorker> = None;
            ctx = WorkerContextThreadSafe { restart_me_writer: Arc::new(Mutex::new(restart_me_writer.try_clone().unwrap())), forkedworker: Arc::new(Mutex::new(forkedworker)), ctx: Arc::new(Mutex::new(WorkerContext {name: name.to_string(), config: config.clone(), config_filename: config_file_name.clone(), event_writer, tap_dev, restart_me_writer: restart_me_writer.try_clone().unwrap()})) };
            ctx.run_worker_process();
        }
        let eventworker_ctx = eventworker_ctx.clone();
        _eventworker_thread = thread::spawn(move || event_handler(event_reader, eventworker_ctx));
    }
    let mut control_clients: Vec<Option<JoinHandle<()>>> = Vec::new();
    for stream in control_listener.incoming() {
        let name = name.to_string();
        match stream {
            Ok(stream) => {
                let config_file_name = config_file_name.clone();
                let event_handler_ctx = eventworker_ctx.clone();
                let config = config.clone();
                let ctx = ctx.clone();
                control_clients.push(Some(thread::spawn(move || handle_control(config_file_name.as_str(), name.as_str(), stream, event_handler_ctx, config, &ctx))))
            },
            Err(_) => {
                println!("Failed to accept control connection on control socket: {}", socket_file_name);
            }
        }
        control_clients.retain_mut(|c| {
            let client = c.take();
            if let Some(client) = client {
                if client.is_finished() {
                    client.join().unwrap();
                    false
                } else {
                    c.replace(client);
                    true
                }
            } else {
                false
            }
        });
    }
    ExitCode::from(0)
}