use std::io::{Read, Write};
use std::net::TcpStream;
use serde::{Deserialize, Serialize};
use crate::handshake::EndpointSecurity;

pub struct Endpoint {
    pub connection: TcpStream,
    pub endpoint_security: EndpointSecurity,
    buf: Vec<u8>,
    pub name: Option<String>
}

#[repr(u16)]
pub enum EndpointMessage {
    PAIRING_REQUEST = 0,
    PAIRING_RESPONSE = 1,
    UPLINK = 2,
    GENERIC_ERROR = 3,
}

#[derive(Serialize, Deserialize)]
pub struct PairingRequest {
    pub name: String
}

#[derive(Serialize, Deserialize)]
pub struct PairingResponse {
    pub name: String
}

impl Endpoint {
    pub fn new(connection: TcpStream, endpoint_security: EndpointSecurity) -> Self {
        Self {
            connection,
            endpoint_security,
            buf: Vec::new(),
            name: None
        }
    }
    pub fn try_clone(&self) -> Result<Self,()> {
        Ok(Self {
            connection: match self.connection.try_clone() {
                Ok(c) => c,
                Err(_) => return Err(())
            },
            endpoint_security: self.endpoint_security.clone(),
            buf: Vec::new(),
            name: None
        })
    }
    pub fn send(&mut self, endpoint_message: EndpointMessage, message_body: &[u8]) -> Result<(),()> {
        self.buf.resize(2+message_body.len(), 0);
        let msg_type = endpoint_message as u16;
        self.buf[0..2].copy_from_slice(msg_type.to_be_bytes().as_slice());
        self.buf[2..].copy_from_slice(message_body);
        match self.endpoint_security.encryption_out.encrypt(&mut self.buf) {
            Ok(_) => {},
            Err(_) => return Err(())
        };
        let msg_len = self.buf.len();
        self.buf.resize(msg_len+4, 0);
        for i in 0..msg_len {
            self.buf[msg_len - i + 3] = self.buf[msg_len - i - 1];
        }
        let msg_len = msg_len as u32;
        self.buf[0..4].copy_from_slice(&msg_len.to_be_bytes());
        match self.connection.write(self.buf.as_slice()) {
            Ok(s) => if s != self.buf.len() {
                println!("Connection write error, closing");
                return Err(())
            },
            Err(_) => {
                println!("Connection write error, closing");
                return Err(())
            }
        };
        Ok(())
    }
    pub fn recv(&mut self, buf: &mut Vec<u8>) -> Result<EndpointMessage,()> {
        self.buf.resize(4, 0);
        match self.connection.read_exact(self.buf.as_mut_slice()) {
            Ok(_) => {},
            Err(_) => {
                println!("Connection read error, closing");
                return Err(())
            }
        };
        let mut msg_size: [u8; 4] = [0; 4];
        msg_size.copy_from_slice(&self.buf);
        let msg_size: u32 = u32::from_be_bytes(msg_size);
        let msg_size: usize = msg_size as usize;
        self.buf.resize(msg_size, 0);
        match self.connection.read_exact(self.buf.as_mut_slice()) {
            Ok(_) => {},
            Err(_) => {
                println!("Connection read error, closing");
                return Err(())
            }
        };
        match self.endpoint_security.encryption_in.decrypt(&mut self.buf) {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to decrypt message");
                return Err(())
            }
        };
        let msg_type: [u8; 2] = [self.buf[0], self.buf[1]];
        let msg_type: u16 = u16::from_be_bytes(msg_type);
        const PAIRING_REQUEST: u16 = EndpointMessage::PAIRING_REQUEST as u16;
        const PAIRING_RESPONSE: u16 = EndpointMessage::PAIRING_RESPONSE as u16;
        const UPLINK: u16 = EndpointMessage::UPLINK as u16;
        const GENERIC_ERROR: u16 = EndpointMessage::GENERIC_ERROR as u16;
        let msg_type: EndpointMessage = match msg_type {
            PAIRING_REQUEST => EndpointMessage::PAIRING_REQUEST,
            PAIRING_RESPONSE => EndpointMessage::PAIRING_RESPONSE,
            UPLINK => EndpointMessage::UPLINK,
            GENERIC_ERROR => EndpointMessage::GENERIC_ERROR,
            _ => {
                println!("Unknown message type");
                return Err(())
            }
        };
        buf.resize(self.buf.len()-2, 0);
        for i in 2..self.buf.len() {
            buf[i-2] = self.buf[i];
        }
        Ok(msg_type)
    }
}