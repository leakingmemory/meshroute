use std::sync::{Arc, Mutex};
use crate::{daemon, endpoint, uplink};

pub struct Uplink {
}

pub fn run_uplink(uplinks: Arc<Mutex<Vec<Arc<Mutex<uplink::Uplink>>>>>, endpoint: &mut endpoint::Endpoint) {
    
}