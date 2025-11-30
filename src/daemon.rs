use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::thread;
use std::thread::JoinHandle;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::Signature;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use crate::{config, controlproto, keyex, opts};
use crate::controlproto::Command;

fn handle_control(name: &str, mut stream: UnixStream) {
    let greeting = controlproto::Greeting {
        name: name.to_string(),
        major: 0,
        minor: 0
    };
    let msg = match bson::serialize_to_vec(&greeting) {
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
        match stream.read(&mut cmdbuf) {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to read length for control protocol");
                return;
            }
        }
        let cmd = u32::from_be_bytes(cmdbuf);
        const EXIT: u32 = Command::EXIT as u32;
        match cmd {
            EXIT => return,
            _ => {
                println!("Unknown command: {}", cmd);
                return;
            }
        };
    }
}

pub fn run_daemon(opts: &opts::Opts, name: &str) -> ExitCode {
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
    let mut config = match config::Config::from_file(config_file_name.as_str()) {
        Ok(config) => config,
        Err(_) => return ExitCode::from(1)
    };
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
        let public_key = match rsa::RsaPublicKey::from_pkcs1_der(match config.master_key {Some(ref master_key) => master_key, None => {
            println!("Failed to load master key. Cannot verify node key.");
            return ExitCode::from(1);
        }}.public_key.as_slice()) {
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
        let priv_key = RsaPrivateKey::from_pkcs8_der(match config.master_key {Some(ref master_key) => master_key, None => {
            println!("Failed to load master key. Cannot generate node key.");
            return ExitCode::from(1);
        }}.private_key.as_slice()).unwrap();
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
    let mut control_clients: Vec<Option<JoinHandle<()>>> = Vec::new();
    for stream in control_listener.incoming() {
        let name = name.to_string();
        match stream {
            Ok(stream) => control_clients.push(Some(thread::spawn(move || handle_control(name.as_str(), stream)))),
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