use std::mem;

use log::info;
use sentinel_common::{EventHeader, ExecveEvent, HookType, MemfdEvent};

use super::Detector;
use crate::core::SharedTracker;

pub struct FilelessDetector;

impl Detector for FilelessDetector {
    fn name(&self) -> &str {
        "Fileless Execution Detector"
    }

    fn on_event(&self, header: &EventHeader, data: &[u8], tracker: &SharedTracker) {
        let ptr = data.as_ptr();

        match header.event_type {
            HookType::Memfd => {
                if data.len() < mem::size_of::<MemfdEvent>() {
                    return;
                }
                let event = unsafe { (ptr as *const MemfdEvent).read_unaligned() };

                let name = String::from_utf8_lossy(&event.filename)
                    .trim_matches('\0')
                    .to_string();

                // Update State
                tracker
                    .lock()
                    .unwrap()
                    .add_active(header.pid, event.fd, &event.filename);

                info!(
                    "ℹ️  [TRACK] PID {} created memfd FD {} ('{}')",
                    header.pid, event.fd, name
                );
            }
            HookType::Execve => {
                if data.len() < mem::size_of::<ExecveEvent>() {
                    return;
                }
                let event = unsafe { (ptr as *const ExecveEvent).read_unaligned() };

                let mut state = tracker.lock().unwrap();
                if let Some(map) = state.get(&header.pid)
                    && let Some(name) = map.get(&event.fd)
                {
                    println!("🚨 [ALERT] FILELESS EXECUTION DETECTED!");
                    println!("    PID:   {}", header.pid);
                    println!("    FD:    {}", event.fd);
                    println!("    Name:  {}", name);
                }
            }
            _ => {} // Ignore other events
        }
    }
}
