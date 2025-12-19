use std::process::ExitCode;
use crate::control::connect_control;
use crate::{controlproto, opts};

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
    match control.command(controlproto::Command::EXIT) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send exit command to control socket");
            return ExitCode::from(1)
        }
    };
    ExitCode::from(0)
}