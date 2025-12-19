use std::collections::HashMap;
use std::io::{Read, Write};
use std::iter::Map;
use std::net::TcpStream;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::Signature;
use rsa::RsaPublicKey;
use rsa::signature::Verifier;
use crate::config;

const PROTO_VERSION_MAJOR: u16 = 0;
const PROTO_VERSION_MINOR: u16 = 0;

pub fn send_pubkeys(connection: &mut TcpStream, config: &Arc<Mutex<config::Config>>, version_major: u16, version_minor: u16) -> Result<(),()> {
    let master_pubkey;
    let node_pubkey;
    let node_sig;
    {
        let config = config.lock().unwrap();
        master_pubkey = match config.master_key {
            Some(ref master_key) => master_key.public_key.clone(),
            None => {
                println!("Cannot handle connections without a master key");
                return Err(());
            }
        };
        (node_pubkey, node_sig) = match config.node_key {
            Some(ref node_key) => (node_key.key.public_key.clone(), node_key.signature.clone()),
            None => {
                println!("Cannot handle connections without a node key");
                return Err(());
            }
        };
    }
    let proto: u32 = 0x3E585E73;
    let master_pubkey_size = master_pubkey.len() as u32;
    let node_pubkey_size = node_pubkey.len() as u32;
    let node_sig_size = node_sig.len() as u32;
    let mut hdrbuf = [0u8; 20];
    hdrbuf[0..4].copy_from_slice(&proto.to_be_bytes());
    hdrbuf[4..6].copy_from_slice(&version_major.to_be_bytes());
    hdrbuf[6..8].copy_from_slice(&version_minor.to_be_bytes());
    hdrbuf[8..12].copy_from_slice(&master_pubkey_size.to_be_bytes());
    hdrbuf[12..16].copy_from_slice(&node_pubkey_size.to_be_bytes());
    hdrbuf[16..20].copy_from_slice(&node_sig_size.to_be_bytes());
    if match connection.write(&hdrbuf) {
        Ok(s) => s,
        Err(_) => 0
    } != hdrbuf.len() {
        println!("External connection write error, closing");
        return Err(());
    }
    if match connection.write(master_pubkey.as_slice()) {
        Ok(s) => s,
        Err(_) => 0
    } != master_pubkey.len() {
        println!("External connection write error, closing");
        return Err(());
    }
    if match connection.write(node_pubkey.as_slice()) {
        Ok(s) => s,
        Err(_) => 0
    } != node_pubkey.len() {
        println!("External connection write error, closing");
        return Err(());
    }
    if match connection.write(node_sig.as_slice()) {
        Ok(s) => s,
        Err(_) => 0
    } != node_sig.len() {
        println!("External connection write error, closing");
        return Err(());
    }
    Ok(())
}

pub struct RecvProtoAndKeys {
    pub master_pubkey: Vec<u8>,
    pub node_pubkey: Vec<u8>,
    pub version_major: u16,
    pub version_minor: u16
}

fn recv_pubkeys(connection: &mut TcpStream) -> Result<RecvProtoAndKeys,()> {
    let mut master_pubkey: Vec<u8> = Vec::new();
    let mut node_pubkey: Vec<u8> = Vec::new();
    let mut node_sig: Vec<u8> = Vec::new();
    let version_major: u16;
    let version_minor: u16;
    {
        let mut hdrbuf = [0u8; 20];
        match match connection.read(&mut hdrbuf) {
            Ok(s) => if s == 20 { Ok(()) } else { Err(()) },
            Err(_) => Err(())
        } {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to read pubkey data header");
                return Err(());
            }
        }
        let mut u32buf = [0u8; 4];
        u32buf.copy_from_slice(&hdrbuf[0..4]);
        let proto = u32::from_be_bytes(u32buf);
        let mut u16buf = [0u8; 2];
        u16buf.copy_from_slice(&hdrbuf[4..6]);
        version_major = u16::from_be_bytes(u16buf);
        u16buf.copy_from_slice(&hdrbuf[6..8]);
        version_minor = u16::from_be_bytes(u16buf);
        u32buf.copy_from_slice(&hdrbuf[8..12]);
        let master_pubkey_size = u32::from_be_bytes(u32buf);
        u32buf.copy_from_slice(&hdrbuf[12..16]);
        let node_pubkey_size = u32::from_be_bytes(u32buf);
        u32buf.copy_from_slice(&hdrbuf[16..20]);
        let node_sig_size = u32::from_be_bytes(u32buf);
        if proto != 0x3E585E73 {
            println!("Protocol error");
            return Err(());
        }
        if master_pubkey_size > 65536 || node_pubkey_size > 65536 || node_sig_size > 65536 {
            println!("Pubkey or signature sizes out of reasonable range");
            return Err(());
        }
        master_pubkey.resize(master_pubkey_size as usize, 0);
        node_pubkey.resize(node_pubkey_size as usize, 0);
        node_sig.resize(node_sig_size as usize, 0);
    }
    if match connection.read(&mut master_pubkey) {
        Ok(s) => s,
        Err(_) => {
            println!("Failed to read master pubkey");
            return Err(());
        }
    } != master_pubkey.len() {
        println!("Failed to read master pubkey (len mismatch)");
        return Err(());
    }
    if match connection.read(&mut node_pubkey) {
        Ok(s) => s,
        Err(_) => {
            println!("Failed to read node pubkey");
            return Err(());
        }
    } != node_pubkey.len() {
        println!("Failed to read node pubkey (len mismatch)");
        return Err(());
    }
    if match connection.read(&mut node_sig) {
        Ok(s) => s,
        Err(_) => {
            println!("Failed to read node signature");
            return Err(());
        }
    } != node_sig.len() {
        println!("Failed to read node signature (len mismatch)");
        return Err(());
    }

    {
        let master_public_key = match RsaPublicKey::from_pkcs1_der(master_pubkey.as_slice()) {
            Ok(k) => k,
            Err(_) => {
                println!("Failed to read master public key");
                return Err(());
            }
        };
        let signature = match Signature::try_from(node_sig.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                println!("Failed to read node signature");
                return Err(());
            }
        };
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new_unprefixed(master_public_key);
        match verifying_key.verify(node_pubkey.as_slice(), &signature) {
            Ok(()) => println!("Node key is valid"),
            Err(e) => {
                println!("Signature verification failed: {:?}", e);
                return Err(())
            },
        }
    }

    Ok(RecvProtoAndKeys {master_pubkey, node_pubkey, version_major, version_minor})
}

const SERVER_VERSION_MIN: u16 = 0;
const SERVER_VERSION_MAX: u16 = 0;
const SERVER_MINOR_VERSION_MIN: [(u16, u16); 1] = [(0u16, 0u16)];
const SERVER_MINOR_VERSION_MAX: [(u16, u16); 1] = [(0u16, 0u16)];

pub fn run_server_handshake(connection: &mut TcpStream, config: &Arc<Mutex<config::Config>>) -> Result<RecvProtoAndKeys,()> {
    match send_pubkeys(connection, config, PROTO_VERSION_MAJOR, PROTO_VERSION_MINOR) {
        Ok(_) => {},
        Err(_) => return Err(())
    }
    let recv_pkeys = match recv_pubkeys(connection) {
        Ok(r) => r,
        Err(_) => return Err(())
    };
    if recv_pkeys.version_major < SERVER_VERSION_MIN || recv_pkeys.version_major > SERVER_VERSION_MAX {
        println!("Protocol major version is out of acceptable range {}-{}: {}", SERVER_VERSION_MIN, SERVER_VERSION_MAX, recv_pkeys.version_major);
        return Err(())
    }
    for minor_min in SERVER_MINOR_VERSION_MIN {
        if recv_pkeys.version_major == minor_min.0 {
            if recv_pkeys.version_minor < minor_min.1 {
                println!("Protocol minor version is out of acceptable range {}-: {}", minor_min.1, recv_pkeys.version_minor);
                return Err(());
            }
        }
    }
    for minor_max in SERVER_MINOR_VERSION_MAX {
        if recv_pkeys.version_major == minor_max.0 {
            if recv_pkeys.version_minor > minor_max.1 {
                println!("Protocol minor version is out of acceptable range -{}: {}", minor_max.1, recv_pkeys.version_minor);
                return Err(());
            }
        }
    }
    Ok(recv_pkeys)
}

const CLIENT_VERSION_MIN: u16 = 0;
const CLIENT_VERSION_MAX: u16 = 0;
const CLIENT_MINOR_VERSION_MIN: [(u16, u16); 1] = [(0u16, 0u16)];
const CLIENT_MINOR_VERSION_MAX: [(u16, u16); 1] = [(0u16, 0u16)];
pub fn run_client_handshake(connection: &mut TcpStream, config: &Arc<Mutex<config::Config>>) -> Result<RecvProtoAndKeys,()> {
    let mut recv_pkeys = match recv_pubkeys(connection) {
        Ok(r) => r,
        Err(_) => return Err(())
    };
    if recv_pkeys.version_major < CLIENT_VERSION_MIN || recv_pkeys.version_major > CLIENT_VERSION_MAX {
        println!("Protocol major version is out of acceptable range {}-{}: {}", CLIENT_VERSION_MIN, CLIENT_VERSION_MAX, recv_pkeys.version_major);
        return Err(())
    }
    for minor_min in CLIENT_MINOR_VERSION_MIN {
        if recv_pkeys.version_major == minor_min.0 {
            if recv_pkeys.version_minor < minor_min.1 {
                println!("Protocol minor version is out of acceptable range {}-: {}", minor_min.1, recv_pkeys.version_minor);
                return Err(());
            }
        }
    }
    for minor_max in SERVER_MINOR_VERSION_MAX {
        if recv_pkeys.version_major == minor_max.0 {
            if recv_pkeys.version_minor > minor_max.1 {
                println!("Protocol minor version is out of acceptable range -{}: {}, downgrading to {}", minor_max.1, recv_pkeys.version_minor, minor_max.1);
                recv_pkeys.version_minor = minor_max.1;
            }
        }
    }
    match send_pubkeys(connection, config, recv_pkeys.version_major, recv_pkeys.version_minor) {
        Ok(_) => {},
        Err(_) => return Err(())
    }
    Ok(recv_pkeys)
}
