use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub struct TrackerState {
    active: HashMap<u32, HashMap<u32, String>>,
}

impl Default for TrackerState {
    fn default() -> Self {
        Self::new()
    }
}

impl TrackerState {
    pub fn new() -> Self {
        TrackerState {
            active: HashMap::new(),
        }
    }

    pub fn add_active(&mut self, pid: u32, fd: u32, filename: &[u8]) {
        let name = String::from_utf8_lossy(filename)
            .trim_matches('\0')
            .to_string();

        self.active
            .entry(pid)
            .or_default()
            .insert(fd, name.to_string());
    }
    pub fn get(&mut self, pid: &u32) -> Option<&HashMap<u32, String>> {
        self.active.get(pid)
    }
}
pub type SharedTracker = Arc<Mutex<TrackerState>>;
