use std::process::ExitCode;
use crate::control::connect_control;
use crate::{controlproto, opts};

pub fn run_ping(opts: &opts::Opts, name: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1)
    };
    println!("{} responds with version {}.{}", control.greeting.name, control.greeting.major, control.greeting.minor);
    match control.command(controlproto::Command::EXIT) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send exit command to control socket");
            return ExitCode::from(1)
        }
    };
    ExitCode::from(0)
}
