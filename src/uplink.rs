use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::net::TcpStream;
use serde::{Deserialize, Serialize};
use bson::{deserialize_from_slice, serialize_to_vec};
use crate::{endpoint, uplink};

// An uplink is a connection to another endpoint
// We may have multiple uplinks to the same endpoint
// circular connections are allowed
pub struct Uplink {
    // The connection to the remote endpoint
    pub connection: TcpStream,
    // The encryption context for outgoing messages
    pub encryption_out: crate::encryption::KeyAndNonce,
    // The hash of the master public key of the remote endpoint
    pub remote_endpoint_hash: Vec<u8>,
    // What endpoints can be reached through this endpoint, not including this endpoint
    pub reachable_endpoints: Vec<Vec<u8>>,
    // Which reachable endpoints have we reported to the endpoint
    pub reported_endpoints: Vec<Vec<u8>>
}

impl Uplink {
    pub fn new(connection: TcpStream, encryption_out: crate::encryption::KeyAndNonce, remote_endpoint_hash: Vec<u8>) -> Self {
        Self {
            connection,
            encryption_out,
            remote_endpoint_hash,
            reachable_endpoints: Vec::new(),
            reported_endpoints: Vec::new()
        }
    }
    
    pub fn send_my_connections(&mut self, key_hashes: Vec<Vec<u8>>) -> Result<(), ()> {
        let msg = MyConnections { key_hashes };
        let mut msg_body = match serialize_to_vec(&msg) {
            Ok(b) => b,
            Err(_) => return Err(())
        };
        let mut buf = Vec::with_capacity(msg_body.len() + 2);
        let msg_type = UplinkMsgType::MY_CONNECTIONS as u16;
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.append(&mut msg_body);
        
        match self.encryption_out.encrypt(&mut buf) {
            Ok(_) => {},
            Err(_) => return Err(())
        }
        
        let mut final_buf = Vec::with_capacity(buf.len() + 4);
        let msg_len = buf.len() as u32;
        final_buf.extend_from_slice(&msg_len.to_be_bytes());
        final_buf.extend_from_slice(&buf);
        
        match self.connection.write_all(&final_buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }
}

#[repr(u16)]
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
enum UplinkMsgType {
    MY_CONNECTIONS = 0,
    PACKET = 1
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MyConnections {
    pub key_hashes: Vec<Vec<u8>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UplinkPacket {
    pub source: Vec<u8>,
    pub trail: Vec<Vec<u8>>,
    pub destination: Vec<u8>,
    pub payload: Vec<u8>,
    pub serial: u32
}

fn calculate_reportable_endpoints(target_endpoint_hash: &[u8], uplinks: &Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>) -> Vec<Vec<u8>> {
    let mut reportable = HashSet::new();
    let uplinks_lock = uplinks.lock().unwrap().clone();
    
    for uplink_arc in uplinks_lock.iter() {
        let uplink = uplink_arc.lock().unwrap();
        
        // If the uplink is to the target endpoint, we don't follow links through it
        if uplink.remote_endpoint_hash == target_endpoint_hash {
            continue;
        }
        
        // Include the remote endpoint itself (if it's not the target endpoint)
        if uplink.remote_endpoint_hash != target_endpoint_hash {
            reportable.insert(uplink.remote_endpoint_hash.clone());
        }
        
        // Include all endpoints reachable through this uplink
        for reachable in &uplink.reachable_endpoints {
            // But never report the target endpoint back to itself
            if reachable != target_endpoint_hash {
                reportable.insert(reachable.clone());
            }
        }
    }
    
    reportable.into_iter().collect()
}

fn update_all_uplinks(uplinks: &Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>) -> usize {
    let uplinks_cloned = uplinks.lock().unwrap().clone();
    let mut reportable_map = HashMap::new();
    
    for uplink_arc in &uplinks_cloned {
        let remote_endpoint_hash = {
            let uplink = uplink_arc.lock().unwrap();
            uplink.remote_endpoint_hash.clone()
        };
        
        // We might have multiple uplinks to the same endpoint.
        // But the reportable list depends only on the remote endpoint hash.
        if !reportable_map.contains_key(&remote_endpoint_hash) {
            let reportable = calculate_reportable_endpoints(&remote_endpoint_hash, uplinks);
            reportable_map.insert(remote_endpoint_hash, reportable);
        }
    }
    
    let mut updated_count = 0;
    for uplink_arc in &uplinks_cloned {
        let mut uplink = uplink_arc.lock().unwrap();
        if let Some(reportable) = reportable_map.get(&uplink.remote_endpoint_hash) {
            let mut changed = reportable.len() != uplink.reported_endpoints.len();
            if !changed {
                let mut reported_set: HashSet<&Vec<u8>> = uplink.reported_endpoints.iter().collect();
                for r in reportable {
                    if !reported_set.contains(r) {
                        changed = true;
                        break;
                    }
                }
            }
            
            if changed {
                match uplink.send_my_connections(reportable.clone()) {
                    Ok(_) => {
                        uplink.reported_endpoints = reportable.clone();
                        updated_count += 1;
                    },
                    Err(_) => {
                        println!("Failed to send MyConnections update to an uplink");
                    }
                }
            }
        }
    }
    
    updated_count
}

fn uplink_change(uplinks: &Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>) {
    while update_all_uplinks(uplinks) > 0 {}
}

pub fn run_uplink(uplinks: Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>, endpoint: &mut endpoint::Endpoint) {
    let current_uplink = Arc::new(Mutex::new(uplink::Uplink::new(endpoint.connection.try_clone().unwrap(), endpoint.endpoint_security.encryption_out.clone(), endpoint.endpoint_security.master_pubkey_sha256.clone())));
    {
        let mut uplinks_lock = uplinks.lock().unwrap();
        uplinks_lock.push(current_uplink.clone());
    }
    uplink_change(&uplinks);
    let mut len_buf = [0u8; 4];
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match endpoint.connection.read_exact(&mut len_buf) {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to read length of transmission");
                break;
            }
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        buf.resize(len, 0);
        match endpoint.connection.read_exact(&mut buf) {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to read transmission");
                break;
            }
        }
        match endpoint.endpoint_security.encryption_in.decrypt(&mut buf) {
            Ok(_) => {},
            Err(_) => {
                println!("Failed to decrypt transmission");
                break;
            }
        }
        if buf.len() < 2 {
            println!("Transmission too short for message type");
            break;
        }
        let msg_type_bytes: [u8; 2] = [buf[0], buf[1]];
        let msg_type_u16 = u16::from_be_bytes(msg_type_bytes);

        const MY_CONNECTIONS: u16 = UplinkMsgType::MY_CONNECTIONS as u16;
        const PACKET: u16 = UplinkMsgType::PACKET as u16;

        match msg_type_u16 {
            MY_CONNECTIONS => {
                match deserialize_from_slice::<MyConnections>(&buf[2..]) {
                    Ok(msg) => {
                        println!("Received MyConnections from {}: {:?}", endpoint.endpoint_security.master_pubkey_sha256.iter().map(|b| format!("{:02x}", b)).collect::<String>(), msg);
                        {
                            let mut uplink_lock = current_uplink.lock().unwrap();
                            uplink_lock.reachable_endpoints = msg.key_hashes;
                        }
                        uplink_change(&uplinks);
                    },
                    Err(_) => {
                        println!("Failed to deserialize MyConnections message");
                    }
                }
            },
            PACKET => {
                match deserialize_from_slice::<UplinkPacket>(&buf[2..]) {
                    Ok(_msg) => {
                        // For now, don't implement actually doing anything
                        // println!("Received UplinkPacket: {:?}", _msg);
                    },
                    Err(_) => {
                        println!("Failed to deserialize UplinkPacket message");
                    }
                }
            },
            _ => {
                println!("Received unknown uplink message type: {}", msg_type_u16);
            }
        }
    }
    {
        let mut uplinks_lock = uplinks.lock().unwrap();
        uplinks_lock.retain(|u| !Arc::ptr_eq(u, &current_uplink));
    }
}