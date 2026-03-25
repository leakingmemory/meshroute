use crate::ethernet::EthernetAddress;
use crate::{endpoint, ethernet, ethertable, filedes, serialwindow, uplink};
use bson::{deserialize_from_slice, serialize_to_vec};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

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
    pub reported_endpoints: Vec<Vec<u8>>,
    pub mac_table: Arc<Mutex<ethertable::MacTable>>,
}

impl Uplink {
    pub fn new(
        connection: TcpStream,
        encryption_out: crate::encryption::KeyAndNonce,
        remote_endpoint_hash: Vec<u8>,
    ) -> Self {
        Self {
            connection,
            encryption_out,
            remote_endpoint_hash,
            reachable_endpoints: Vec::new(),
            reported_endpoints: Vec::new(),
            mac_table: Arc::new(Mutex::new(ethertable::MacTable::new())),
        }
    }

    pub fn send_my_connections(&mut self, key_hashes: Vec<Vec<u8>>) -> Result<(), ()> {
        let msg = MyConnections { key_hashes };
        let mut msg_body = match serialize_to_vec(&msg) {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        let mut buf = Vec::with_capacity(msg_body.len() + 2);
        let msg_type = UplinkMsgType::MY_CONNECTIONS as u16;
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.append(&mut msg_body);

        match self.encryption_out.encrypt(&mut buf) {
            Ok(_) => {}
            Err(_) => return Err(()),
        }

        let mut final_buf = Vec::with_capacity(buf.len() + 4);
        let msg_len = buf.len() as u32;
        final_buf.extend_from_slice(&msg_len.to_be_bytes());
        final_buf.extend_from_slice(&buf);

        match self.connection.write_all(&final_buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub fn send_packet(&mut self, packet: &UplinkPacket) -> Result<(), ()> {
        let mut msg_body = match serialize_to_vec(packet) {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        let mut buf = Vec::with_capacity(msg_body.len() + 2);
        let msg_type = UplinkMsgType::PACKET as u16;
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.append(&mut msg_body);

        match self.encryption_out.encrypt(&mut buf) {
            Ok(_) => {}
            Err(_) => return Err(()),
        }

        let mut final_buf = Vec::with_capacity(buf.len() + 4);
        let msg_len = buf.len() as u32;
        final_buf.extend_from_slice(&msg_len.to_be_bytes());
        final_buf.extend_from_slice(&buf);

        match self.connection.write_all(&final_buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub fn send_reset_serial(&mut self, serial: u32) -> Result<(), ()> {
        let msg = ResetSerial { serial };
        let mut msg_body = match serialize_to_vec(&msg) {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        let mut buf = Vec::with_capacity(msg_body.len() + 2);
        let msg_type = UplinkMsgType::RESET_SERIAL as u16;
        buf.extend_from_slice(&msg_type.to_be_bytes());
        buf.append(&mut msg_body);

        match self.encryption_out.encrypt(&mut buf) {
            Ok(_) => {}
            Err(_) => return Err(()),
        }

        let mut final_buf = Vec::with_capacity(buf.len() + 4);
        let msg_len = buf.len() as u32;
        final_buf.extend_from_slice(&msg_len.to_be_bytes());
        final_buf.extend_from_slice(&buf);

        match self.connection.write_all(&final_buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

#[repr(u16)]
#[derive(Serialize, Deserialize, Debug)]
#[allow(non_camel_case_types)]
enum UplinkMsgType {
    MY_CONNECTIONS = 0,
    PACKET = 1,
    RESET_SERIAL = 2,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MyConnections {
    pub key_hashes: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ResetSerial {
    pub serial: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UplinkPacket {
    pub source: Vec<u8>,
    pub trail: Vec<Vec<u8>>,
    pub destination: Vec<u8>,
    pub payload: Vec<u8>,
    pub serial: u32,
}

fn calculate_reportable_endpoints(
    target_endpoint_hash: &[u8],
    uplinks: &Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>,
) -> Vec<Vec<u8>> {
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
                let reported_set: HashSet<&Vec<u8>> = uplink.reported_endpoints.iter().collect();
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
                    }
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

pub fn forward_packet(
    packet: &UplinkPacket,
    uplinks: &Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>,
) {
    let mut uplinks_lock = uplinks.lock().unwrap().clone();
    let mut rng = thread_rng();
    uplinks_lock.shuffle(&mut rng);
    let multicast = packet.destination.is_empty();

    if multicast {
        for uplink_arc in &uplinks_lock {
            let mut uplink = uplink_arc.lock().unwrap();

            // Don't send to any uplink that is in the trail-list
            let mut in_trail = false;
            for t in &packet.trail {
                if *t == uplink.remote_endpoint_hash {
                    in_trail = true;
                    break;
                }
            }
            if in_trail {
                continue;
            }

            match uplink.send_packet(packet) {
                Ok(_) => {}
                Err(_) => {
                    println!("Failed to forward multicast packet to an uplink");
                }
            }
        }
    } else {
        // Unicast: check for direct links first
        let mut sent = false;
        for uplink_arc in &uplinks_lock {
            let mut uplink = uplink_arc.lock().unwrap();

            // Don't send to any uplink that is in the trail-list
            let mut in_trail = false;
            for t in &packet.trail {
                if *t == uplink.remote_endpoint_hash {
                    in_trail = true;
                    break;
                }
            }
            if in_trail {
                continue;
            }

            if uplink.remote_endpoint_hash == packet.destination {
                match uplink.send_packet(packet) {
                    Ok(_) => {
                        sent = true;
                        break; // Sent successfully, don't send over other direct links
                    }
                    Err(_) => {
                        println!("Failed to forward unicast packet to a direct uplink");
                    }
                }
            }
        }

        if !sent {
            // No direct link found, try reachable endpoints
            for uplink_arc in &uplinks_lock {
                let mut uplink = uplink_arc.lock().unwrap();

                // Don't send to any uplink that is in the trail-list
                let mut in_trail = false;
                for t in &packet.trail {
                    if *t == uplink.remote_endpoint_hash {
                        in_trail = true;
                        break;
                    }
                }
                if in_trail {
                    continue;
                }

                let mut matches = false;
                for r in &uplink.reachable_endpoints {
                    if *r == packet.destination {
                        matches = true;
                        break;
                    }
                }

                if matches {
                    match uplink.send_packet(packet) {
                        Ok(_) => {
                            break; // Sent successfully, don't send over other indirect links
                        }
                        Err(_) => {
                            println!("Failed to forward unicast packet to a reachable uplink");
                        }
                    }
                }
            }
        }
    }
}

pub fn frame_to_raw(frame: &ethernet::EthernetFrame) -> Vec<u8> {
    frame.to_raw()
}

pub fn run_uplink(
    tap_dev: Arc<Mutex<filedes::FileDes>>,
    my_pubkey_hash: Vec<u8>,
    uplinks: Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>,
    uplink_mac_tables: Arc<Mutex<HashMap<Vec<u8>, Arc<Mutex<ethertable::MacTable>>>>>,
    uplink_serial_window: Arc<
        Mutex<HashMap<Vec<u8>, Arc<Mutex<serialwindow::SerialWindow<u32, 128>>>>>,
    >,
    endpoint: &mut endpoint::Endpoint,
    serial: Arc<AtomicU32>,
) {
    println!("Run uplink");
    let current_uplink = Arc::new(Mutex::new(uplink::Uplink::new(
        endpoint.connection.try_clone().unwrap(),
        endpoint.endpoint_security.encryption_out.clone(),
        endpoint.endpoint_security.master_pubkey_sha256.clone(),
    )));
    {
        let mut current_uplink = current_uplink.lock().unwrap();
        let mut uplink_mac_tables = uplink_mac_tables.lock().unwrap();
        if uplink_mac_tables.contains_key(&current_uplink.remote_endpoint_hash) {
            current_uplink.mac_table = uplink_mac_tables
                .get(&current_uplink.remote_endpoint_hash)
                .unwrap()
                .clone();
        } else {
            uplink_mac_tables.insert(
                current_uplink.remote_endpoint_hash.clone(),
                Arc::new(Mutex::new(ethertable::MacTable::new())),
            );
        }
    }
    {
        let mut uplinks_lock = uplinks.lock().unwrap();
        uplinks_lock.push(current_uplink.clone());
    }
    {
        let mut uplink_lock = current_uplink.lock().unwrap();
        let current_serial = serial.load(Ordering::SeqCst);
        if let Err(_) = uplink_lock.send_reset_serial(current_serial) {
            println!("Failed to send ResetSerial message");
        }
    }
    uplink_change(&uplinks);
    let mut len_buf = [0u8; 4];
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match endpoint.connection.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(_) => {
                println!("Failed to read length of transmission");
                break;
            }
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        buf.resize(len, 0);
        match endpoint.connection.read_exact(&mut buf) {
            Ok(_) => {}
            Err(_) => {
                println!("Failed to read transmission");
                break;
            }
        }
        match endpoint.endpoint_security.encryption_in.decrypt(&mut buf) {
            Ok(_) => {}
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
        const RESET_SERIAL: u16 = UplinkMsgType::RESET_SERIAL as u16;

        match msg_type_u16 {
            MY_CONNECTIONS => match deserialize_from_slice::<MyConnections>(&buf[2..]) {
                Ok(msg) => {
                    println!(
                        "Received MyConnections from {}: {:?}",
                        endpoint
                            .endpoint_security
                            .master_pubkey_sha256
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>(),
                        msg
                    );
                    {
                        let mut uplink_lock = current_uplink.lock().unwrap();
                        uplink_lock.reachable_endpoints = msg.key_hashes;
                    }
                    uplink_change(&uplinks);
                }
                Err(_) => {
                    println!("Failed to deserialize MyConnections message");
                }
            },
            PACKET => {
                match deserialize_from_slice::<UplinkPacket>(&buf[2..]) {
                    Ok(mut _msg) => {
                        let master_pubkey = endpoint.endpoint_security.master_pubkey_sha256.clone();
                        let accept_it = {
                            let mut uplink_serial_window = uplink_serial_window.lock().unwrap();
                            let uplink_serial_window =
                                if uplink_serial_window.contains_key(&_msg.source) {
                                    uplink_serial_window.get(&_msg.source).unwrap().clone()
                                } else {
                                    let new_serial_window: Arc<
                                        Mutex<serialwindow::SerialWindow<u32, 128>>,
                                    > = Arc::new(Mutex::new(serialwindow::SerialWindow::new(0u32)));
                                    uplink_serial_window
                                        .insert(_msg.source.clone(), new_serial_window.clone());
                                    new_serial_window
                                };
                            let mut uplink_serial_window = uplink_serial_window.lock().unwrap();
                            if !uplink_serial_window.observed(_msg.serial) {
                                uplink_serial_window.observe(_msg.serial);
                                true
                            } else {
                                false
                            }
                        };
                        _msg.trail.push(master_pubkey);
                        // For now, don't implement actually doing anything
                        let frame: Option<ethernet::EthernetFrame> = if accept_it {
                            match deserialize_from_slice(_msg.payload.as_slice()) {
                                Ok(f) => Some(f),
                                Err(_) => {
                                    println!("Unable to decode frame from uplink");
                                    None
                                }
                            }
                        } else {
                            None
                        };
                        if let Some(frame) = frame {
                            if (&frame.src_mac).is_individual() {
                                let mut mac_tables: Vec<Arc<Mutex<ethertable::MacTable>>> =
                                    Vec::new();
                                let uplink_mac_table = {
                                    let mut uplink_mac_tables = uplink_mac_tables.lock().unwrap();
                                    let mut uplink_mac_table: Option<
                                        Arc<Mutex<ethertable::MacTable>>,
                                    > = None;
                                    for (key, mac_table) in uplink_mac_tables.iter() {
                                        if _msg.source == *key {
                                            uplink_mac_table = Some(mac_table.clone());
                                        } else {
                                            mac_tables.push(mac_table.clone());
                                        }
                                    }
                                    match uplink_mac_table {
                                        Some(mac_table) => mac_table,
                                        None => {
                                            let mac_table =
                                                Arc::new(Mutex::new(ethertable::MacTable::new()));
                                            uplink_mac_tables
                                                .insert(_msg.source.clone(), mac_table.clone());
                                            mac_table
                                        }
                                    }
                                };
                                for mac_table in mac_tables {
                                    let mut mac_table = mac_table.lock().unwrap();
                                    mac_table.remove_entry_if_exists(&frame.src_mac);
                                }
                                let mut uplink_mac_table = uplink_mac_table.lock().unwrap();
                                uplink_mac_table.add_entry_if_not_exists(&frame.src_mac);
                            }
                            if _msg.destination.is_empty() || _msg.destination == my_pubkey_hash {
                                let tap_dev = tap_dev.lock().unwrap();
                                match tap_dev.write_all(frame_to_raw(&frame).as_slice()) {
                                    Ok(_) => {}
                                    Err(_) => {
                                        println!("Failed to write to virtual ethernet device");
                                    }
                                };
                            }
                            if _msg.destination.is_empty() || _msg.destination != my_pubkey_hash {
                                forward_packet(&_msg, &uplinks);
                            }
                        }
                    }
                    Err(_) => {
                        println!("Failed to deserialize UplinkPacket message");
                    }
                }
            }
            RESET_SERIAL => match deserialize_from_slice::<ResetSerial>(&buf[2..]) {
                Ok(msg) => {
                    println!(
                        "Received ResetSerial from {}: {:?}",
                        endpoint
                            .endpoint_security
                            .master_pubkey_sha256
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<String>(),
                        msg
                    );
                    {
                        let mut uplink_serial_window = uplink_serial_window.lock().unwrap();
                        let remote_pubkey_hash =
                            endpoint.endpoint_security.master_pubkey_sha256.clone();
                        if uplink_serial_window.contains_key(&remote_pubkey_hash) {
                            let mut sw = uplink_serial_window
                                .get(&remote_pubkey_hash)
                                .unwrap()
                                .lock()
                                .unwrap();
                            sw.reset(msg.serial);
                        } else {
                            let new_serial_window: Arc<
                                Mutex<serialwindow::SerialWindow<u32, 128>>,
                            > = Arc::new(Mutex::new(serialwindow::SerialWindow::new(msg.serial)));
                            uplink_serial_window.insert(remote_pubkey_hash, new_serial_window);
                        }
                    }
                }
                Err(_) => {
                    println!("Failed to deserialize ResetSerial message");
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
    println!("Uplink connection closed");
}
