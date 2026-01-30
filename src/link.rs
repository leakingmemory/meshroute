use std::process::ExitCode;
use bson::deserialize_from_slice;
use crate::control::connect_control;
use crate::{controlproto, opts};
use crate::controlproto::{Command, ControlMsgType, LinksList, PairingRequestList};

pub fn run_list_links(opts: &opts::Opts, name: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1)
    };
    match control.command(controlproto::Command::LIST_LINKS) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send request for the links list to control socket");
            return ExitCode::from(1)
        }
    };
    let result = match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, ControlMsgType::LINKS_LIST) {
            Ok(match deserialize_from_slice::<LinksList>(buf) {
                Ok(r) => r,
                Err(_) => {
                    println!("Failed to deserialize links list");
                    return Err(());
                }
            })
        } else {
            println!("Links list request failed");
            Err(())
        }
    }) {
        Ok(opt) => opt,
        Err(_) => {
            println!("Failed to receive the links list from control socket");
            return ExitCode::from(1)
        }
    };
    for item in result.links {
        println!("{}", item)
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

pub fn run_addrem_link(opts: &opts::Opts, name: &str, cmd: controlproto::Command, link: &str) -> ExitCode {
    let mut control = match connect_control(opts, name) {
        Ok(c) => c,
        Err(_) => return ExitCode::from(1)
    };
    match control.command_with_object(cmd, &controlproto::LinkCmd {
        name: link.to_string()
    }) {
        Ok(()) => {},
        Err(_) => {
            println!("Failed to send request to control socket");
            return ExitCode::from(1)
        }
    };
    match control.receive(|hdr, buf| {
        if matches!(hdr.msg_type, ControlMsgType::GENERIC_OK) {
            Ok(())
        } else {
            println!("Add/remove link request failed");
            return Err(())
        }
    }) {
        Ok(_) => {},
        Err(_) => {
            println!("Add/remove link request failed");
            return ExitCode::from(1)
        }
    };
    ExitCode::from(0)
}

pub fn run_add_link(opts: &opts::Opts, name: &str, link: &str) -> ExitCode {
    run_addrem_link(opts, name, Command::ADD_LINK, link)
}

pub fn run_remove_link(opts: &opts::Opts, name: &str, link: &str) -> ExitCode {
    run_addrem_link(opts, name, Command::REMOVE_LINK, link)
}
