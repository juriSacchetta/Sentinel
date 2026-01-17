use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};


pub struct TrackerState {
    // Step 1: Holding area (PID -> Filename waiting for FD)
    pending: HashMap<u32, String>,
    
    // Step 2: Active area (PID -> (FD -> Filename))
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
            pending: HashMap::new(),
            active: HashMap::new(),
        }
    }

    pub fn insert_pending(&mut self, pid: u32, filename: String) {
        self.pending.insert(pid, filename);
    }

    pub fn promote_to_active(&mut self, pid: u32, fd: u32) {
        if let Some(filename) = self.pending.remove(&pid) {
            let entry = self.active.entry(pid).or_default();
            entry.insert(fd, filename);
        }
    }

    pub fn get_active(&self, pid: &u32) -> Option<&HashMap<u32, String>> {
        self.active.get(pid)
    }
}
pub type SharedTracker = Arc<Mutex<TrackerState>>;
