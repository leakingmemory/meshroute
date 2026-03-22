use crate::control::connect_control;
use crate::controlproto::ControlMsgType::PairingResponse;
use crate::controlproto::{ControlMsgType, PairResult, PairedList, PairingRequestList};
use crate::{controlproto, opts};
use bson::deserialize_from_slice;
use std::process::ExitCode;

pub fn run_pair(opts: &opts::Opts, name: &str, addr: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1),
    };
    let pair_cmd = controlproto::PairCmd {
        addr: addr.to_string(),
    };
    match control.command_with_object(controlproto::Command::Pair, &pair_cmd) {
        Ok(()) => {}
        Err(_) => {
            println!("Failed to send pairing request command to control socket");
            return ExitCode::from(1);
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, PairingResponse) {
            Ok(match deserialize_from_slice::<PairResult>(buf) {
                Ok(r) => r,
                Err(_) => {
                    println!("Failed to deserialize pairing response");
                    return Err(());
                }
            })
        } else {
            println!("Pairing failed");
            Err(())
        }
    }) {
        Ok(opt) => opt,
        Err(_) => {
            println!("Failed to receive pairing response from control socket");
            return ExitCode::from(1);
        }
    };
    println!(
        "Run on the other end: meshroute accept \"{}\" \"{:x?}\"",
        result.remote_name,
        result.master_pubkey_sha256.as_slice()
    );
    ExitCode::from(0)
}

pub fn short_key_hash(hash: &[u8]) -> String {
    let mut str: Option<String> = None;
    if hash.len() > 0 {
        str = Some(format!("{:X}", hash[0]));
        if let Some(ref mut str) = str
            && hash.len() > 1
        {
            str.push_str(" ...");
            if hash.len() > 2 {
                if hash.len() > 5 {
                    str.push_str(
                        format!(
                            " {:X} {:X} {:X}",
                            hash[hash.len() - 3],
                            hash[hash.len() - 2],
                            hash[hash.len() - 1]
                        )
                        .as_str(),
                    )
                } else {
                    str.push_str(format!(" {:X}", hash[hash.len() - 1]).as_str());
                }
            }
        }
    }
    str.unwrap_or_else(|| "".to_string())
}

pub fn run_list_pairing_requests(opts: &opts::Opts, name: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1),
    };
    match control.command(controlproto::Command::ListPairingRequests) {
        Ok(()) => {}
        Err(_) => {
            println!("Failed to send request for the pairing request list to control socket");
            return ExitCode::from(1);
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, ControlMsgType::PairingRequestList) {
            Ok(match deserialize_from_slice::<PairingRequestList>(buf) {
                Ok(r) => r,
                Err(_) => {
                    println!("Failed to deserialize pairing request list");
                    return Err(());
                }
            })
        } else {
            println!("Pairing request list request failed");
            Err(())
        }
    }) {
        Ok(opt) => opt,
        Err(_) => {
            println!("Failed to receive the pairing request list from control socket");
            return ExitCode::from(1);
        }
    };
    for item in result.requests {
        let utc_expires = chrono::DateTime::<chrono::Utc>::from_timestamp(item.expires, 0);
        let local_expires = match utc_expires {
            Some(utc) => Some(chrono::DateTime::<chrono::Local>::from(utc)),
            None => None,
        };
        match local_expires {
            Some(local_expires) => println!(
                "{} {} {}",
                short_key_hash(item.master_pubkey_sha256.as_slice()),
                item.name,
                local_expires.format("%Y-%m-%d %H:%M:%S %:z")
            ),
            None => println!(
                "{} {} {}",
                short_key_hash(item.master_pubkey_sha256.as_slice()),
                item.name,
                item.expires
            ),
        }
    }
    match control.command(controlproto::Command::Exit) {
        Ok(()) => {}
        Err(_) => {
            println!("Failed to send exit command to control socket");
            return ExitCode::from(1);
        }
    };
    ExitCode::from(0)
}

pub fn run_list_paired(opts: &opts::Opts, name: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1),
    };
    match control.command(controlproto::Command::ListPairedEndpoints) {
        Ok(()) => {}
        Err(_) => {
            println!("Failed to send request for the pairing request list to control socket");
            return ExitCode::from(1);
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, ControlMsgType::PairedList) {
            Ok(match deserialize_from_slice::<PairedList>(buf) {
                Ok(r) => r,
                Err(_) => {
                    println!("Failed to deserialize pairing request list");
                    return Err(());
                }
            })
        } else {
            println!("Pairing request list request failed");
            Err(())
        }
    }) {
        Ok(opt) => opt,
        Err(_) => {
            println!("Failed to receive the pairing request list from control socket");
            return ExitCode::from(1);
        }
    };
    for item in result.endpoints {
        println!("{:x?} {}", item.master_pubkey_sha256.as_slice(), item.name);
    }
    match control.command(controlproto::Command::Exit) {
        Ok(()) => {}
        Err(_) => {
            println!("Failed to send exit command to control socket");
            return ExitCode::from(1);
        }
    };
    ExitCode::from(0)
}

fn is_whitespace(ch: u8) -> bool {
    ch == b' ' || ch == b'\t' || ch == b'\n' || ch == b'\r'
}

fn hex_digit(ch: u8) -> Result<u8, ()> {
    if ch >= b'0' && ch <= b'9' {
        Ok(ch - b'0')
    } else if ch >= b'a' && ch <= b'f' {
        Ok(ch - b'a' + 10)
    } else if ch >= b'A' && ch <= b'F' {
        Ok(ch - b'A' + 10)
    } else {
        Err(())
    }
}

pub fn parse_key_hash(key_hash: &str) -> Result<[u8; 32], ()> {
    let mut i = 0;
    let key_hash = key_hash.as_bytes();
    while i < key_hash.len() && is_whitespace(key_hash[i]) {
        i += 1;
    }
    if i >= key_hash.len() || key_hash[i] != b'[' {
        println!("Expected key hash parameter to start with [");
        return Err(());
    }
    i += 1;
    let mut j = 0;
    let mut output = [0u8; 32];
    while i < key_hash.len() {
        while i < key_hash.len() && is_whitespace(key_hash[i]) {
            i += 1;
        }
        if i >= key_hash.len() || key_hash[i] == b']' {
            break;
        }
        if j >= output.len() {
            println!("Expected ], hash too long");
            return Err(());
        }
        let dig1 = match hex_digit(key_hash[i]) {
            Ok(d) => d,
            Err(_) => {
                println!("Expected hex digit or ]");
                return Err(());
            }
        };
        i += 1;
        if i >= key_hash.len() {
            println!("Expected ]");
            return Err(());
        }
        if key_hash[i] == b']' {
            output[j] = dig1;
            j += 1;
            break;
        }
        if is_whitespace(key_hash[i]) {
            output[j] = dig1;
            j += 1;
            i += 1;
        } else if key_hash[i] == b',' {
            output[j] = dig1;
            j += 1;
            i += 1;
            continue;
        } else {
            let dig2 = match hex_digit(key_hash[i]) {
                Ok(d) => d,
                Err(_) => {
                    println!("Expected hex digit, , or ]");
                    return Err(());
                }
            };
            i += 1;
            output[j] = (dig1 << 4) + dig2;
            j += 1;
        }
        while i < key_hash.len() && is_whitespace(key_hash[i]) {
            i += 1;
        }
        if i >= key_hash.len() {
            println!("Expected ]");
            return Err(());
        }
        if key_hash[i] == b']' {
            break;
        }
        if key_hash[i] != b',' {
            println!("Expected , or ]");
            return Err(());
        }
        i += 1;
    }
    if i >= key_hash.len() || key_hash[i] != b']' {
        println!("Expected ]");
        return Err(());
    }
    i += 1;
    while i < key_hash.len() && is_whitespace(key_hash[i]) {
        i += 1;
    }
    if i < key_hash.len() {
        println!("Unexpected trailing characters");
        return Err(());
    }
    if j < output.len() {
        println!("Hash too short");
        return Err(());
    }
    Ok(output)
}

pub fn run_accept(opts: &opts::Opts, name: &str, key_hash: &str) -> ExitCode {
    let key_hash = match parse_key_hash(key_hash) {
        Ok(k) => k,
        Err(_) => return ExitCode::from(1),
    };
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1),
    };
    let pair_cmd = controlproto::AcceptPairingCmd { key_hash };
    match control.command_with_object(controlproto::Command::AcceptPairing, &pair_cmd) {
        Ok(()) => {}
        Err(_) => {
            println!("Failed to send pairing request command to control socket");
            return ExitCode::from(1);
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, PairingResponse) {
            Ok(match deserialize_from_slice::<PairResult>(buf) {
                Ok(r) => r,
                Err(_) => {
                    println!("Failed to deserialize pairing response");
                    return Err(());
                }
            })
        } else {
            println!("Pairing failed");
            Err(())
        }
    }) {
        Ok(opt) => opt,
        Err(_) => {
            println!("Failed to receive pairing response from control socket");
            return ExitCode::from(1);
        }
    };
    println!(
        "Run on the other end: meshroute finish \"{}\" \"{:x?}\"",
        result.remote_name,
        result.master_pubkey_sha256.as_slice()
    );
    ExitCode::from(0)
}

pub fn run_finish(opts: &opts::Opts, name: &str, key_hash: &str) -> ExitCode {
    let key_hash = match parse_key_hash(key_hash) {
        Ok(k) => k,
        Err(_) => return ExitCode::from(1),
    };
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1),
    };
    let pair_cmd = controlproto::AcceptPairingCmd { key_hash };
    match control.command_with_object(controlproto::Command::AcceptPairing, &pair_cmd) {
        Ok(()) => {}
        Err(_) => {
            println!("Failed to send pairing request command to control socket");
            return ExitCode::from(1);
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, PairingResponse) {
            Ok(match deserialize_from_slice::<PairResult>(buf) {
                Ok(r) => r,
                Err(_) => {
                    println!("Failed to deserialize pairing response");
                    return Err(());
                }
            })
        } else {
            println!("Pairing failed");
            Err(())
        }
    }) {
        Ok(opt) => opt,
        Err(_) => {
            println!("Failed to receive pairing response from control socket");
            return ExitCode::from(1);
        }
    };
    println!("Finished pairing with {}", result.remote_name);
    ExitCode::from(0)
}
