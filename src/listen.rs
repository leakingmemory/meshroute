use std::process::ExitCode;
use crate::control::connect_control;
use crate::{controlproto, opts};

pub fn run_listen(opts: &opts::Opts, name: &str, listen: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1)
    };
    let listen_cmd = controlproto::ListenCmd { listen: listen.to_string() };
    match control.command_with_object(controlproto::Command::LISTEN, &listen_cmd) {
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
