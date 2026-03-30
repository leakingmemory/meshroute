use crate::{config, encryption};
use rand::RngCore;
use rsa::oaep::{DecryptingKey, EncryptingKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::traits::{Decryptor, PublicKeyParts, RandomizedEncryptor};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Digest;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

const PROTO_VERSION_MAJOR: u16 = 0;
const PROTO_VERSION_MINOR: u16 = 0;

pub fn sign(data: &[u8], privkey: RsaPrivateKey) -> Result<Vec<u8>, ()> {
    let signing_key = SigningKey::<sha2::Sha512>::new_unprefixed(privkey);
    let signature = signing_key.sign(data);
    let signature = signature.to_vec();
    Ok(signature)
}

pub fn verify(data: &[u8], signature: &[u8], pubkey: RsaPublicKey) -> Result<(), ()> {
    let verification_key = VerifyingKey::<sha2::Sha512>::new_unprefixed(pubkey);
    let signature = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => {
            return Err(());
        }
    };
    match verification_key.verify(data, &signature) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

pub fn encrypt(data: &[u8], pubkey: &[u8]) -> Result<Vec<u8>, ()> {
    let pubkey = match RsaPublicKey::from_pkcs1_der(pubkey) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Failed to read public key");
            return Err(());
        }
    };
    let encrypting_key = EncryptingKey::<sha2::Sha256>::new(pubkey);
    let mut rng = rand::thread_rng();
    let encrypted = match encrypting_key.encrypt_with_rng(&mut rng, data) {
        Ok(e) => e,
        Err(_) => {
            eprintln!("Failed to encrypt data");
            return Err(());
        }
    };
    Ok(encrypted)
}

pub fn send_pubkeys(
    connection: &mut TcpStream,
    config: &Arc<Mutex<config::Config>>,
    version_major: u16,
    version_minor: u16,
) -> Result<(), ()> {
    let master_pubkey;
    let node_pubkey;
    let node_sig;
    {
        let config = config.lock().unwrap();
        master_pubkey = match config.master_key {
            Some(ref master_key) => master_key.public_key.clone(),
            None => {
                eprintln!("Cannot handle connections without a master key");
                return Err(());
            }
        };
        (node_pubkey, node_sig) = match config.node_key {
            Some(ref node_key) => (node_key.key.public_key.clone(), node_key.signature.clone()),
            None => {
                eprintln!("Cannot handle connections without a node key");
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
    if let Err(_) = connection.write_all(&hdrbuf) {
        eprintln!("External connection write error, closing");
        return Err(());
    }
    if let Err(_) = connection.write_all(master_pubkey.as_slice()) {
        eprintln!("External connection write error, closing");
        return Err(());
    }
    if let Err(_) = connection.write_all(node_pubkey.as_slice()) {
        eprintln!("External connection write error, closing");
        return Err(());
    }
    if let Err(_) = connection.write_all(node_sig.as_slice()) {
        eprintln!("External connection write error, closing");
        return Err(());
    }
    Ok(())
}

pub struct RecvProtoAndKeys {
    pub master_pubkey: Vec<u8>,
    pub node_pubkey: Vec<u8>,
    pub version_major: u16,
    pub version_minor: u16,
}

fn recv_pubkeys(connection: &mut TcpStream) -> Result<RecvProtoAndKeys, ()> {
    let mut master_pubkey: Vec<u8> = Vec::new();
    let mut node_pubkey: Vec<u8> = Vec::new();
    let mut node_sig: Vec<u8> = Vec::new();
    let version_major: u16;
    let version_minor: u16;
    {
        let mut hdrbuf = [0u8; 20];
        if let Err(_) = connection.read_exact(&mut hdrbuf) {
            eprintln!("Failed to read pubkey data header");
            return Err(());
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
            eprintln!("Protocol error");
            return Err(());
        }
        if master_pubkey_size > 65536 || node_pubkey_size > 65536 || node_sig_size > 65536 {
            eprintln!("Pubkey or signature sizes out of reasonable range");
            return Err(());
        }
        master_pubkey.resize(master_pubkey_size as usize, 0);
        node_pubkey.resize(node_pubkey_size as usize, 0);
        node_sig.resize(node_sig_size as usize, 0);
    }
    if let Err(_) = connection.read_exact(&mut master_pubkey) {
        eprintln!("Failed to read master pubkey");
        return Err(());
    }
    if let Err(_) = connection.read_exact(&mut node_pubkey) {
        eprintln!("Failed to read node pubkey");
        return Err(());
    }
    if let Err(_) = connection.read_exact(&mut node_sig) {
        eprintln!("Failed to read node signature");
        return Err(());
    }

    {
        let master_public_key = match RsaPublicKey::from_pkcs1_der(master_pubkey.as_slice()) {
            Ok(k) => k,
            Err(_) => {
                eprintln!("Failed to read master public key");
                return Err(());
            }
        };
        let signature = match Signature::try_from(node_sig.as_slice()) {
            Ok(s) => s,
            Err(_) => {
                eprintln!("Failed to read node signature");
                return Err(());
            }
        };
        let verifying_key =
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new_unprefixed(master_public_key);
        match verifying_key.verify(node_pubkey.as_slice(), &signature) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Signature verification failed: {:?}", e);
                return Err(());
            }
        }
    }

    Ok(RecvProtoAndKeys {
        master_pubkey,
        node_pubkey,
        version_major,
        version_minor,
    })
}

fn generate_key_and_nonce(input: &[u8]) -> Result<encryption::KeyAndNonce, ()> {
    let hsv = sha2::Sha512::digest(input);
    let hs = hsv.as_slice();
    let mut counter_bytes = [0u8; 16];
    counter_bytes.copy_from_slice(&hs[48..64]);
    let mut key = [0u8; 32];
    let mut nonce_prefix = [0u8; 16];
    let counter = u128::from_be_bytes(counter_bytes);
    key.copy_from_slice(&hs[0..32]);
    nonce_prefix.copy_from_slice(&hs[32..48]);
    encryption::KeyAndNonce::new(key, nonce_prefix, counter)
}

fn send_init(
    connection: &mut TcpStream,
    recv_pkeys: &RecvProtoAndKeys,
    config: &Arc<Mutex<config::Config>>,
) -> Result<encryption::KeyAndNonce, ()> {
    let pubkey = match RsaPublicKey::from_pkcs1_der(recv_pkeys.node_pubkey.as_slice()) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Failed to read public key");
            return Err(());
        }
    };
    let mut keys;
    let mut init_block_signature;
    {
        let mut init_block;
        {
            let block_of_material_size = pubkey.size() - 66;
            let mut block_of_material: Vec<u8> = Vec::new();
            block_of_material.resize(block_of_material_size, 0);
            let mut rng = rand::thread_rng();
            rng.fill_bytes(block_of_material.as_mut_slice());
            keys = match generate_key_and_nonce(block_of_material.as_slice()) {
                Ok(k) => k,
                Err(_) => {
                    eprintln!("Failed to generate key and nonce");
                    return Err(());
                }
            };
            {
                let node_key = match config.lock().unwrap().node_key {
                    Some(ref node_key) => {
                        match RsaPrivateKey::from_pkcs8_der(node_key.key.private_key.as_slice()) {
                            Ok(k) => k,
                            Err(_) => {
                                eprintln!("Failed to read private key");
                                return Err(());
                            }
                        }
                    }
                    None => {
                        eprintln!("Cannot handle connections without a node key");
                        return Err(());
                    }
                };
                init_block_signature = match sign(block_of_material.as_slice(), node_key) {
                    Ok(s) => s,
                    Err(_) => {
                        eprintln!("Failed to sign block of material");
                        return Err(());
                    }
                };
            }
            init_block = match encrypt(
                block_of_material.as_slice(),
                recv_pkeys.node_pubkey.as_slice(),
            ) {
                Ok(e) => e,
                Err(_) => {
                    eprintln!("Failed to encrypt block of material");
                    return Err(());
                }
            };
        }
        let len = init_block.len();
        init_block.resize(len + 16, 0);
        for i in 0..len {
            init_block[len - i + 15] = init_block[len - i - 1];
        }
        match keys.encrypt(&mut init_block_signature) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Failed to encrypt init block signature");
                return Err(());
            }
        }
        init_block[0..8].copy_from_slice(&len.to_be_bytes());
        init_block[8..16].copy_from_slice(&init_block_signature.len().to_be_bytes());
        if let Err(_) = connection.write_all(init_block.as_slice()) {
            eprintln!("External connection write error, closing");
            return Err(());
        }
    }
    if let Err(_) = connection.write_all(init_block_signature.as_slice()) {
        eprintln!("External connection write error, closing");
        return Err(());
    }
    Ok(keys)
}

fn recv_init(
    connection: &mut TcpStream,
    recv_pkeys: &RecvProtoAndKeys,
    config: &Arc<Mutex<config::Config>>,
) -> Result<encryption::KeyAndNonce, ()> {
    let mut block_of_material_buf: Vec<u8> = Vec::new();
    let block_of_material_len;
    {
        block_of_material_buf.resize(16, 0);
        if let Err(_) = connection.read_exact(block_of_material_buf.as_mut_slice()) {
            eprintln!("External connection read error, closing");
            return Err(());
        }
        let mut u64buf = [0u8; 8];
        u64buf.copy_from_slice(&block_of_material_buf[0..8]);
        block_of_material_len = u64::from_be_bytes(u64buf) as usize;
        u64buf.copy_from_slice(&block_of_material_buf[8..16]);
        let block_of_material_siglen = u64::from_be_bytes(u64buf) as usize;
        block_of_material_buf.resize(block_of_material_len + block_of_material_siglen, 0);
        match connection.read_exact(block_of_material_buf.as_mut_slice()) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("External connection read error, closing");
                return Err(());
            }
        }
    }
    let decryption_key = match config.lock().unwrap().node_key {
        Some(ref node_key) => {
            match RsaPrivateKey::from_pkcs8_der(node_key.key.private_key.as_slice()) {
                Ok(k) => k,
                Err(_) => {
                    eprintln!("Failed to read private key");
                    return Err(());
                }
            }
        }
        None => {
            eprintln!("Cannot handle connections without a node key");
            return Err(());
        }
    };
    let decryption_key = DecryptingKey::<sha2::Sha256>::new(decryption_key);
    let block_of_material =
        match decryption_key.decrypt(&block_of_material_buf[0..block_of_material_len]) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("Failed to decrypt block of material");
                return Err(());
            }
        };
    let mut keys = match generate_key_and_nonce(block_of_material.as_slice()) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Failed to generate key and nonce");
            return Err(());
        }
    };
    let mut signature: Vec<u8> = Vec::new();
    signature.resize(block_of_material_buf.len() - block_of_material_len, 0);
    signature
        .as_mut_slice()
        .copy_from_slice(&block_of_material_buf[block_of_material_len..]);
    match keys.decrypt(&mut signature) {
        Ok(_) => {}
        Err(_) => {
            eprintln!("Failed to decrypt signature");
            return Err(());
        }
    };
    let verification_key = match RsaPublicKey::from_pkcs1_der(recv_pkeys.node_pubkey.as_slice()) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Failed to read public key");
            return Err(());
        }
    };
    match verify(
        block_of_material.as_slice(),
        signature.as_slice(),
        verification_key,
    ) {
        Ok(_) => {}
        Err(_) => {
            eprintln!("Signature verification failed");
            return Err(());
        }
    }
    Ok(keys)
}

#[derive(Clone)]
pub struct EndpointSecurity {
    pub master_pubkey_sha256: Vec<u8>,
    pub encryption_out: encryption::KeyAndNonce,
    pub encryption_in: encryption::KeyAndNonce,
}

const SERVER_VERSION_MIN: u16 = 0;
const SERVER_VERSION_MAX: u16 = 0;
const SERVER_MINOR_VERSION_MIN: [(u16, u16); 1] = [(0u16, 0u16)];
const SERVER_MINOR_VERSION_MAX: [(u16, u16); 1] = [(0u16, 0u16)];

pub fn run_server_handshake(
    connection: &mut TcpStream,
    config: &Arc<Mutex<config::Config>>,
) -> Result<EndpointSecurity, ()> {
    if let Err(_) = connection.set_read_timeout(Some(std::time::Duration::from_secs(60))) {
        eprintln!("Failed to set read timeout on connection");
        return Err(());
    }
    match send_pubkeys(connection, config, PROTO_VERSION_MAJOR, PROTO_VERSION_MINOR) {
        Ok(_) => {}
        Err(_) => return Err(()),
    }
    let recv_pkeys = match recv_pubkeys(connection) {
        Ok(r) => r,
        Err(_) => return Err(()),
    };
    if recv_pkeys.version_major < SERVER_VERSION_MIN
        || recv_pkeys.version_major > SERVER_VERSION_MAX
    {
        eprintln!(
            "Protocol major version is out of acceptable range {}-{}: {}",
            SERVER_VERSION_MIN, SERVER_VERSION_MAX, recv_pkeys.version_major
        );
        return Err(());
    }
    for minor_min in SERVER_MINOR_VERSION_MIN {
        if recv_pkeys.version_major == minor_min.0 {
            if recv_pkeys.version_minor < minor_min.1 {
                eprintln!(
                    "Protocol minor version is out of acceptable range {}-: {}",
                    minor_min.1, recv_pkeys.version_minor
                );
                return Err(());
            }
        }
    }
    for minor_max in SERVER_MINOR_VERSION_MAX {
        if recv_pkeys.version_major == minor_max.0 {
            if recv_pkeys.version_minor > minor_max.1 {
                eprintln!(
                    "Protocol minor version is out of acceptable range -{}: {}",
                    minor_max.1, recv_pkeys.version_minor
                );
                return Err(());
            }
        }
    }
    let encryption_out = match send_init(connection, &recv_pkeys, config) {
        Ok(keys) => keys,
        Err(_) => return Err(()),
    };
    let encryption_in = match recv_init(connection, &recv_pkeys, config) {
        Ok(keys) => keys,
        Err(_) => return Err(()),
    };
    let master_pubkey_sha256 = sha2::Sha256::digest(recv_pkeys.master_pubkey.as_slice())
        .as_slice()
        .to_vec();
    Ok(EndpointSecurity {
        master_pubkey_sha256,
        encryption_out,
        encryption_in,
    })
}

const CLIENT_VERSION_MIN: u16 = 0;
const CLIENT_VERSION_MAX: u16 = 0;
const CLIENT_MINOR_VERSION_MIN: [(u16, u16); 1] = [(0u16, 0u16)];
pub fn run_client_handshake(
    connection: &mut TcpStream,
    config: &Arc<Mutex<config::Config>>,
) -> Result<EndpointSecurity, ()> {
    if let Err(_) = connection.set_read_timeout(Some(std::time::Duration::from_secs(60))) {
        eprintln!("Failed to set read timeout on connection");
        return Err(());
    }
    let mut recv_pkeys = match recv_pubkeys(connection) {
        Ok(r) => r,
        Err(_) => return Err(()),
    };
    if recv_pkeys.version_major < CLIENT_VERSION_MIN
        || recv_pkeys.version_major > CLIENT_VERSION_MAX
    {
        eprintln!(
            "Protocol major version is out of acceptable range {}-{}: {}",
            CLIENT_VERSION_MIN, CLIENT_VERSION_MAX, recv_pkeys.version_major
        );
        return Err(());
    }
    for minor_min in CLIENT_MINOR_VERSION_MIN {
        if recv_pkeys.version_major == minor_min.0 {
            if recv_pkeys.version_minor < minor_min.1 {
                eprintln!(
                    "Protocol minor version is out of acceptable range {}-: {}",
                    minor_min.1, recv_pkeys.version_minor
                );
                return Err(());
            }
        }
    }
    for minor_max in SERVER_MINOR_VERSION_MAX {
        if recv_pkeys.version_major == minor_max.0 {
            if recv_pkeys.version_minor > minor_max.1 {
                eprintln!(
                    "Protocol minor version is out of acceptable range -{}: {}, downgrading to {}",
                    minor_max.1, recv_pkeys.version_minor, minor_max.1
                );
                recv_pkeys.version_minor = minor_max.1;
            }
        }
    }
    match send_pubkeys(
        connection,
        config,
        recv_pkeys.version_major,
        recv_pkeys.version_minor,
    ) {
        Ok(_) => {}
        Err(_) => return Err(()),
    }
    let encryption_out = match send_init(connection, &recv_pkeys, config) {
        Ok(keys) => keys,
        Err(_) => return Err(()),
    };
    let encryption_in = match recv_init(connection, &recv_pkeys, config) {
        Ok(keys) => keys,
        Err(_) => return Err(()),
    };
    let master_pubkey_sha256 = sha2::Sha256::digest(recv_pkeys.master_pubkey.as_slice())
        .as_slice()
        .to_vec();
    Ok(EndpointSecurity {
        master_pubkey_sha256,
        encryption_out,
        encryption_in,
    })
}
