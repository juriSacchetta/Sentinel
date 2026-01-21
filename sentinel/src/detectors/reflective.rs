use std::mem;

use log::warn;
use sentinel_common::{EventHeader, HookType, MmapEvent};

use super::Detector;
use crate::core::{DescriptorType, ProcessRegistry};

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

        // Filter for W^X violation: PROT_WRITE (0x2) | PROT_EXEC (0x4)
        const PROT_WRITE: u32 = 0x2;
        const PROT_EXEC: u32 = 0x4;
        if (event.prot & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC) {
            return;
        }

        let process_lock = registry.get_or_create(header.pid);
        let process = process_lock.lock().unwrap();

        // Only alert if mapping from a tracked memfd (anonymous executable memory)
        if let Some(DescriptorType::Memfd { name }) = process.fds.get(&event.fd) {
            warn!(
                "🚨 REFLECTIVE CODE LOADING DETECTED! PID: {} mmap(PROT_WRITE|PROT_EXEC) from memfd FD {} ('{}')",
                header.pid, event.fd, name
            );
        }
    }
}
