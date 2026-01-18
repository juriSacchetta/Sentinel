use std::mem;

use log::info;
use sentinel_common::{EventHeader, ExecveEvent, HookType, MemfdEvent};

use super::Detector;
use crate::core::{DescriptorType, ProcessRegistry};

pub struct FilelessDetector;

impl Detector for FilelessDetector {
    fn name(&self) -> &str {
        "Fileless Execution Detector"
    }

    fn on_event(&self, header: &EventHeader, data: &[u8], registry: &ProcessRegistry) {
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

                info!(
                    "ℹ️  [TRACK] PID {} created memfd FD {} ('{}')",
                    header.pid, event.fd, name
                );

                let binding = registry.get_or_create(header.pid);
                let mut process = binding.lock().unwrap();
                process.fds.insert(event.fd, DescriptorType::Memfd { name });
            }
            HookType::Execve => {
                if data.len() < mem::size_of::<ExecveEvent>() {
                    return;
                }
                let event = unsafe { (ptr as *const ExecveEvent).read_unaligned() };

                let process_lock = registry.get_or_create(header.pid);
                let process = process_lock.lock().unwrap();

                if let Some(name) = process.fds.get(&event.fd) {
                    println!("🚨 [ALERT] FILELESS EXECUTION DETECTED!");
                    println!("    PID:   {}", process.pid);
                    println!("    FD:    {}", event.fd);
                    println!("    Name:  {}", name);
                }
            }
            _ => {} // Ignore other events
        }
    }
}
