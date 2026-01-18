use std::mem;

use sentinel_common::{EventHeader, HookType, MmapEvent};

use super::Detector;
use crate::core::ProcessRegistry;

pub struct ReflectiveLoaderDetector;

impl Detector for ReflectiveLoaderDetector {
    fn name(&self) -> &str {
        "Reflective Loading Detector"
    }

    fn on_event(&self, header: &EventHeader, data: &[u8], registry: &ProcessRegistry) {
        if header.event_type != HookType::Mmap {
            return;
        }
        let ptr = data.as_ptr();
        if data.len() < mem::size_of::<MmapEvent>() {
            return;
        }

        let event = unsafe { (ptr as *const MmapEvent).read_unaligned() };

        let binding = registry.get_or_create(header.pid);
        let process = binding.lock().unwrap();

        if let Some(name) = process.fds.get(&event.fd) {
            // Kernel pre-filtered for PROT_EXEC, so this is definitely suspicious
            println!("🚨 [ALERT] REFLECTIVE CODE LOADING DETECTED!");
            println!("    PID:    {}", header.pid);
            println!("    FD:     {} ({})", event.fd, name);
            println!("    Action: mmap(PROT_EXEC)");
        }
    }
}
