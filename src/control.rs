use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use crate::{controlproto, opts};
use crate::controlproto::Command;

pub struct ControlClient {
    pub greeting: controlproto::Greeting,
    pub stream: UnixStream
}

pub fn connect_control(opts: &opts::Opts, name: &str) -> Result<ControlClient, ()> {
    let mut socket_file_name = opts.socket_dir.clone();
    if !socket_file_name.ends_with('/') {
        socket_file_name.push('/');
    }
    socket_file_name.insert_str(socket_file_name.len(), name);
    socket_file_name.insert_str(socket_file_name.len(), ".socket");
    let mut stream = match UnixStream::connect(socket_file_name.clone()) {
        Ok(s) => s,
        Err(_) => {
            println!("Failed to connect to control socket: {}", socket_file_name);
            return Err(());
        }
    };
    let mut lenbuf = [0u8; 4];
    match stream.read(&mut lenbuf) {
        Ok(_) => {},
        Err(_) => {
            println!("Failed to read length for control protocol");
            return Err(());
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(u32::from_be_bytes(lenbuf) as usize, 0u8);
    match stream.read(buf.as_mut_slice()) {
        Ok(_) => {},
        Err(_) => {
            println!("Failed to read greeting for control protocol");
            return Err(());
        }
    }
    let greeting = match bson::deserialize_from_slice::<controlproto::Greeting>(buf.as_slice()) {
        Ok(g) => g,
        Err(_) => {
            println!("Failed to deserialize greeting for control protocol");
            return Err(());
        }
    };
    Ok(ControlClient { greeting, stream })
}

impl ControlClient {
    pub(crate) fn command(&mut self, cmd: Command) -> Result<(), ()> {
        match self.stream.write((cmd as u32).to_be_bytes().as_slice()) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }
}
