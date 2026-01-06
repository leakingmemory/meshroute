use std::process::ExitCode;
use bson::deserialize_from_slice;
use crate::control::connect_control;
use crate::{controlproto, opts};
use crate::controlproto::ControlMsgType::PAIRING_RESPONSE;
use crate::controlproto::PairResult;

pub fn run_pair(opts: &opts::Opts, name: &str, addr: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1)
    };
    let pair_cmd = controlproto::PairCmd { addr: addr.to_string() };
    match control.command_with_object(controlproto::Command::PAIR, &pair_cmd) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send listen command to control socket");
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