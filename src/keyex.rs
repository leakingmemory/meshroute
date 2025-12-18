use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct RsaKeyPair {
    #[serde(with = "serde_bytes")]
    pub private_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>
}

#[derive(Serialize, Deserialize)]
pub struct NodeKeyBase {
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    pub replace_after: i64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>
}

#[derive(Clone)]
pub struct NodeKey {
    pub key: RsaKeyPair,
    pub replace_after: chrono::DateTime<chrono::Utc>,
    pub signature: Vec<u8>
}

impl RsaKeyPair {
    pub fn serialize(&self) -> Result<Vec<u8>,()> {
        match bson::serialize_to_vec(self) {
            Ok(v) => Ok(v),
            Err(_) => Err(())
        }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self,()> {
        match bson::deserialize_from_slice::<Self>(data) {
            Ok(c) => Ok(c),
            Err(_) => Err(())
        }
    }
}

impl NodeKey {
    pub fn serialize(&self) -> Result<Vec<u8>,()> {
        let keydata = match self.key.serialize() {
            Ok(d) => d,
            Err(_) => return Err(())
        };
        let timeprim = self.replace_after.timestamp();
        let base = NodeKeyBase {
            key: keydata,
            replace_after: timeprim,
            signature: self.signature.clone()
        };
        match bson::serialize_to_vec(&base) {
            Ok(v) => Ok(v),
            Err(_) => Err(())
        }
    }
    pub fn deserialize(data: &[u8]) -> Result<Self,()> {
        let base = match bson::deserialize_from_slice::<NodeKeyBase>(data) {
            Ok(b) => b,
            Err(_) => return Err(())
        };
        let key = match RsaKeyPair::deserialize(base.key.as_slice()) {
            Ok(k) => k,
            Err(_) => return Err(())
        };
        let replace_after = match chrono::DateTime::from_timestamp(base.replace_after, 0) {
            Some(t) => t,
            None => {
                println!("Failed to parse replace_after timestamp");
                return Err(())
            }
        };
        Ok(Self { key, replace_after, signature: base.signature })
    }
}
