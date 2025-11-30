use std::fs;
use std::io::ErrorKind;
use serde::{Deserialize, Serialize};
use crate::keyex;

#[derive(Serialize, Deserialize)]
pub struct ConfigRecord {
    pub name: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct ConfigBase {
    pub major: u16,
    pub minor: u16,
    pub data: Vec<ConfigRecord>
}

pub struct Config {
    pub master_key: Option<keyex::RsaKeyPair>,
    pub node_key: Option<keyex::NodeKey>
}

impl ConfigBase {
    pub fn new() -> Self {
        Self { major: 0, minor: 0, data: Vec::new() }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self,()> {
        match bson::deserialize_from_slice::<Self>(data) {
            Ok(c) => Ok(c),
            Err(_) => Err(())
        }
    }
    pub fn serialize(&self) -> Result<Vec<u8>,()> {
        match bson::serialize_to_vec(self) {
            Ok(v) => Ok(v),
            Err(_) => Err(())
        }
    }
    pub fn from_file(filename: &str) -> Result<Option<Self>,()> {
        let content = match fs::read(filename) {
            Ok(c) => c,
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    return Ok(None);
                }
                println!("Error reading config file: {}", err);
                return Err(())
            }
        };
        Self::deserialize(content.as_slice()).map(Some)
    }
    pub fn save(&self, filename: &str) -> Result<(),()> {
        let content = self.serialize()?;
        let mut tmp_filename = filename.to_string();
        tmp_filename.push_str(".tmp");
        let um = unsafe { libc::umask(0o077) };
        let result = match fs::write(tmp_filename.clone(), content) {
            Ok(_) => {
                match fs::rename(tmp_filename, filename) {
                    Ok(_) => Ok(()),
                    Err(err) => {
                        println!("Error renaming config file: {}", err);
                        Err(())
                    }
                }
            },
            Err(err) => {
                println!("Error writing config file: {}", err);
                Err(())
            }
        };
        unsafe { libc::umask(um) };
        result
    }
    pub fn get_by_name(&self, name: &str) -> Vec<&ConfigRecord> {
        self.data.iter().filter(|r| r.name == name).collect()
    }
    pub fn get_single_by_name(&self, name: &str) -> Option<&ConfigRecord> {
        let matches = self.get_by_name(name);
        if matches.len() == 1 {
            Some(&matches[0])
        } else {
            None
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self { master_key: None, node_key: None }
    }
    pub fn from_file(filename: &str) -> Result<Self,()> {
        let config = match match ConfigBase::from_file(filename) {
            Ok(c) => c,
            Err(_) => return Err(())
        } {
            Some(c) => c,
            None => return Ok(Self::new())
        };
        let master_key_record = config.get_single_by_name("master_key");
        let master_key = match master_key_record {
            Some(r) => match keyex::RsaKeyPair::deserialize(r.data.as_slice()) {
                Ok(k) => Some(k),
                Err(_) => {
                    println!("Failed to deserialize master key, ignoring");
                    return Err(())
                }
            },
            None => None
        };
        let node_key_record = config.get_single_by_name("node_key");
        let node_key = match node_key_record {
            Some(r) => match keyex::NodeKey::deserialize(r.data.as_slice()) {
                Ok(k) => Some(k),
                Err(_) => {
                    println!("Failed to deserialize node key, ignoring");
                    return Err(())
                }
            },
            None => None
        };
        Ok(Self { master_key, node_key })
    }
    pub fn save(&self, filename: &str) -> Result<(),()> {
        let mut config_base = ConfigBase::new();
        if let Some(master_key) = &self.master_key {
            let master_key_data = match master_key.serialize() {
                Ok(d) => d,
                Err(_) => {
                    println!("Failed to serialize master key");
                    return Err(())
                }
            };
            config_base.data.push(ConfigRecord { name: "master_key".to_string(), data: master_key_data });
        }
        if let Some(node_key) = &self.node_key {
            let node_key_data = match node_key.serialize() {
                Ok(d) => d,
                Err(_) => {
                    println!("Failed to serialize node key");
                    return Err(())
                }
            };
            config_base.data.push(ConfigRecord { name: "node_key".to_string(), data: node_key_data });
        }
        config_base.save(filename)
    }
}