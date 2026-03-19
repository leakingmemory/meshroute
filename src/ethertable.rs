
#[derive(Copy, Clone)]
pub struct MacEntry {
    pub addr: [u8; 6]
}

trait HashMacAddr {
    fn hash_value(&self) -> u16;
}

#[derive(Clone)]
pub struct MacTableLevel3 {
    pub entries: Vec<MacEntry>
}

impl MacTableLevel3 {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }
}

#[derive(Clone)]
pub struct MacTableLevel2 {
    pub entries: [Option<Box<MacTableLevel3>>; 256]
}

impl MacTableLevel2 {
    pub fn new() -> Self {
        Self { entries: [
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
        ] }
    }
}

#[derive(Clone)]
pub struct MacTable {
    pub entries: [Option<Box<MacTableLevel2>>; 256]
}

impl MacTable {
    pub fn new() -> Self {
        Self { entries: [
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
        ] }
    }
    pub fn add_entry_if_not_exists(&mut self, addr: &[u8; 6]) {
        let mac_hash = addr.hash_value();
        println!("hash: {:x}", mac_hash);
        let idx1 = (mac_hash >> 8) as usize;
        let idx2 = (mac_hash & 0xff) as usize;
        let level2 = match self.entries[idx1] {
            Some(ref mut level2) => level2,
            None => {
                self.entries[idx1] = Some(Box::new(MacTableLevel2::new()));
                self.entries[idx1].as_mut().unwrap()
            }
        };
        let level3 = match level2.entries[idx2] {
            Some(ref mut level3) => level3,
            None => {
                level2.entries[idx2] = Some(Box::new(MacTableLevel3::new()));
                level2.entries[idx2].as_mut().unwrap()
            }
        };
        for entry in level3.entries.iter_mut() {
            if entry.addr == *addr {
                return;
            }
        }
        level3.entries.push(MacEntry { addr: *addr });
    }
    pub fn remove_entry_if_exists(&mut self, addr: &[u8; 6]) {
        let mac_hash = addr.hash_value();
        println!("hash: {:x}", mac_hash);
        let idx1 = (mac_hash >> 8) as usize;
        let idx2 = (mac_hash & 0xff) as usize;
        let level2 = match self.entries[idx1] {
            Some(ref mut level2) => level2,
            None => return
        };
        let level3 = match level2.entries[idx2] {
            Some(ref mut level3) => level3,
            None => return
        };
        level3.entries.retain(|entry| entry.addr != *addr);
    }
    pub fn has_entry(&mut self, addr: &[u8; 6]) -> bool {
        let mac_hash = addr.hash_value();
        println!("hash: {:x}", mac_hash);
        let idx1 = (mac_hash >> 8) as usize;
        let idx2 = (mac_hash & 0xff) as usize;
        let level2 = match self.entries[idx1] {
            Some(ref mut level2) => level2,
            None => return false
        };
        let level3 = match level2.entries[idx2] {
            Some(ref mut level3) => level3,
            None => return false
        };
        let addr = addr.clone();
        level3.entries.iter().any(move |&entry| {
            entry.addr == addr
        })
    }
}

impl HashMacAddr for &[u8; 6] {
    fn hash_value(&self) -> u16 {
        let mut u;
        {
            let mut vu = [0u8; 4];
            {
                vu.copy_from_slice(&self[0..4]);
            }
            u = u32::from_le_bytes(vu);
        }
        let mut p;
        {
            let mut vp = [0u8; 2];
            {
                vp.copy_from_slice(&self[4..6]);
            }
            p = u16::from_le_bytes(vp);
        }
        for _i in 0..32 {
            let pbit = (p & 1) as u8;
            p = p >> 1;
            let ubit = (u & 1) as u8;
            u = u >> 1;
            let xbit = pbit ^ ubit;
            if pbit != 0  {
                p |= 0x8000;
            }
            if xbit != 0  {
                p ^= 0x4142;
            }
        }
        p
    }
}