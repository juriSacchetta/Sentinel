use std::mem;

use log::info;
use sentinel_common::EventHeader;

use crate::{core::ProcessRegistry, detectors::Detector};

pub struct EventBus {
    detectors: Vec<Box<dyn Detector>>,
    registry: ProcessRegistry,
}

impl EventBus {
    pub fn new(registry: ProcessRegistry) -> Self {
        Self {
            detectors: Vec::new(),
            registry,
        }
    }

    pub fn register(&mut self, detector: impl Detector + 'static) {
        info!("🔍 Registering detector: {}", detector.name());
        self.detectors.push(Box::new(detector));
    }

    pub fn process_packet(&self, buf: &[u8]) {
        if buf.len() < mem::size_of::<EventHeader>() {
            return;
        }

        // Read Header once
        let ptr = buf.as_ptr();
        let header = unsafe { *(ptr as *const EventHeader) };

        // Dispatch to all detectors
        for detector in &self.detectors {
            detector.on_event(&header, buf, &self.registry);
        }
    }
}
