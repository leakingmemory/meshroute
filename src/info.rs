use std::process::ExitCode;
use bson::deserialize_from_slice;
use crate::control::connect_control;
use crate::{controlproto, opts};

pub fn run_info(opts: &opts::Opts, name: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1)
    };
    match control.command(controlproto::Command::InfoRequest) {
        Ok(_) => {},
        Err(_) => {
            println!("Failed to send info request");
            return ExitCode::from(1);
        }
    }
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, controlproto::ControlMsgType::InfoResponse) {
            Ok(match deserialize_from_slice::<controlproto::InfoResponse>(buf) {
                Ok(r) => r,
                Err(_) => {
                    println!("Failed to deserialize info response");
                    return Err(());
                }
            })
        } else {
            println!("Info request failed");
            Err(())
        }
    }) {
        Ok(opt) => opt,
        Err(_) => {
            println!("Failed to receive info response from control socket");
            return ExitCode::from(1)
        }
    };
    println!("Master key: {:x?}", result.master_pubkey_sha256);
    println!("Node key: {:x?}", result.node_pubkey_sha256);
    let utc_expires = chrono::DateTime::<chrono::Utc>::from_timestamp(result.node_expiry, 0);
    let local_expires = match utc_expires {
        Some(utc) => Some(chrono::DateTime::<chrono::Local>::from(utc)),
        None => None
    };
    match local_expires {
        Some(local_expires) => println!("Node key replacement: {}", local_expires.format("%Y-%m-%d %H:%M:%S %:z")),
        None => println!("Node key replacement: N/A")
    };
    ExitCode::from(0)
}
