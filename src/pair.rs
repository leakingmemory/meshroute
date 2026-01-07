use std::process::ExitCode;
use bson::deserialize_from_slice;
use crate::control::connect_control;
use crate::{controlproto, opts};
use crate::controlproto::ControlMsgType::PAIRING_RESPONSE;
use crate::controlproto::{ControlMsgType, PairResult, PairingRequestList};

pub fn run_pair(opts: &opts::Opts, name: &str, addr: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1)
    };
    let pair_cmd = controlproto::PairCmd { addr: addr.to_string() };
    match control.command_with_object(controlproto::Command::PAIR, &pair_cmd) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send pairing request command to control socket");
            return ExitCode::from(1)
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, PAIRING_RESPONSE) {
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
            return ExitCode::from(1)
        }
    };
    println!("Run on the other end: meshroute accept \"{}\" \"{:x?}\"", result.name, result.master_pubkey_sha256.as_slice());
    ExitCode::from(0)
}

pub fn short_key_hash(hash: &[u8]) -> String {
    let mut str: Option<String> = None;
    if (hash.len() > 0) {
        str = Some(format!("{:X}", hash[0]));
        if let Some(ref mut str) = str && hash.len() > 1 {
            str.push_str(" ...");
            if hash.len() > 2 {
                if hash.len() > 5 {
                    str.push_str(format!(" {:X} {:X} {:X}", hash[hash.len() - 3], hash[hash.len() - 2], hash[hash.len() - 1]).as_str())
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
        Err(_) => return ExitCode::from(1)
    };
    match control.command(controlproto::Command::LIST_PAIRING_REQUESTS) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send request for the pairing request list to control socket");
            return ExitCode::from(1)
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, ControlMsgType::PAIRING_REQUEST_LIST) {
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
            return ExitCode::from(1)
        }
    };
    for item in result.requests {
        let utc_expires = chrono::DateTime::<chrono::Utc>::from_timestamp(item.expires, 0);
        let local_expires = match utc_expires {
            Some(utc) => Some(chrono::DateTime::<chrono::Local>::from(utc)),
            None => None
        };
        match local_expires {
            Some(local_expires) => println!("{} {} {}", short_key_hash(item.master_pubkey_sha256.as_slice()), item.name, local_expires.format("%Y-%m-%d %H:%M:%S %:z")),
            None => println!("{} {} {}", short_key_hash(item.master_pubkey_sha256.as_slice()), item.name, item.expires)
        }
    }
    match control.command(controlproto::Command::EXIT) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send exit command to control socket");
            return ExitCode::from(1)
        }
    };
    ExitCode::from(0)
}
