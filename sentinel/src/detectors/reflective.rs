use std::mem;

use sentinel_common::{EventHeader, HookType, MmapEvent};

use super::Detector;
use crate::core::SharedTracker;

pub struct ReflectiveLoaderDetector;

impl Detector for ReflectiveLoaderDetector {
    fn name(&self) -> &str {
        "Reflective Loading Detector"
    }

    fn on_event(&self, header: &EventHeader, data: &[u8], tracker: &SharedTracker) {
        if header.event_type != HookType::Mmap {
            return;
        }
        let ptr = data.as_ptr();
        if data.len() < mem::size_of::<MmapEvent>() {
            return;
        }
        let event = unsafe { (ptr as *const MmapEvent).read_unaligned() };

        let mut state = tracker.lock().unwrap();
        if let Some(map) = state.get(&header.pid)
            && let Some(name) = map.get(&event.fd)
        {
            // Kernel pre-filtered for PROT_EXEC, so this is definitely suspicious
            println!("🚨 [ALERT] REFLECTIVE CODE LOADING DETECTED!");
            println!("    PID:    {}", header.pid);
            println!("    FD:     {} ({})", event.fd, name);
            println!("    Action: mmap(PROT_EXEC)");
        }
    }
}
