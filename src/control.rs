use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use bson::serialize_to_vec;
use serde::Serialize;
use crate::{controlproto, opts};
use crate::controlproto::{Command, ControlMsgHdr};

pub struct ControlClient {
    pub greeting: controlproto::Greeting,
    pub stream: UnixStream,
    pub buffer: Vec<u8>
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
    let buffer: Vec<u8> = Vec::new();
    Ok(ControlClient { greeting, stream, buffer })
}

impl ControlClient {
    pub(crate) fn command(&mut self, cmd: Command) -> Result<(), ()> {
        match self.stream.write((cmd as u32).to_be_bytes().as_slice()) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }
    pub(crate) fn command_with_object<T>(&mut self, cmd: Command, obj: &T) -> Result<(), ()>
    where T: Serialize {
        let len = match self.stream.write((cmd as u32).to_be_bytes().as_slice()) {
            Ok(len) => len,
            Err(_) => return Err(())
        };
        if len != 4 {
            return Err(());
        }
        let vec = match serialize_to_vec::<T>(obj) {
            Ok(vec) => vec,
            Err(_) => return Err(())
        };
        let len = match self.stream.write((vec.len() as u32).to_be_bytes().as_slice()) {
            Ok(len) => len,
            Err(_) => return Err(())
        };
        if len != 4 {
            return Err(());
        }
        let len = match self.stream.write(vec.as_slice()) {
            Ok(len) => len,
            Err(_) => return Err(())
        };
        if len == vec.len() {
            Ok(())
        } else {
            Err(())
        }
    }
    pub(crate) fn receive<F,T>(&mut self, func: F) -> Result<T,()>
    where F: FnOnce(&ControlMsgHdr, &[u8]) -> Result<T,()> {
        let mut hdrbuf = [0u8; 8];
        let mut off = 0;
        while off < hdrbuf.len() {
            let rd = match self.stream.read(&mut hdrbuf[off..]) {
                Ok(r) => r,
                Err(_) => return Err(())
            };
            off += rd;
        }
        let hdr = match ControlMsgHdr::from_bytes(&hdrbuf) {
            Ok(h) => h,
            Err(_) => return Err(())
        };
        self.buffer.resize(hdr.len as usize, 0u8);
        off = 0;
        while off < self.buffer.len() {
            let rd = match self.stream.read(&mut self.buffer[off..]) {
                Ok(r) => r,
                Err(_) => return Err(())
            };
            off += rd;
        }
        func(&hdr, &self.buffer)
    }
}
