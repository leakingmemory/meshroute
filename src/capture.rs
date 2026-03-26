use crate::control::connect_control;
use crate::{controlproto, ethernet, opts};
use bson::deserialize_from_slice;
use std::process::ExitCode;

pub fn run_capture(opts: &opts::Opts, name: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1),
    };
    match control.command(controlproto::Command::Capture) {
        Ok(()) => {}
        Err(_) => {
            eprintln!("Failed to send exit command to control socket");
            return ExitCode::from(1);
        }
    };
    loop {
        match control.receive(|_hdr, buf| {
            let frame = match deserialize_from_slice::<ethernet::EthernetFrame>(buf) {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("Failed to deserialize network frame");
                    return Err(());
                }
            };
            println!(
                ">> [{}] {:x?} -> {:x?} {:x?} {}",
                if frame.is_multicast() {
                    "multi"
                } else {
                    "single"
                },
                frame.src_mac,
                frame.dst_mac,
                frame.ethertype,
                frame.payload.len()
            );
            Ok(())
        }) {
            Ok(_) => {}
            Err(_) => break,
        };
    }
    ExitCode::from(1)
}
