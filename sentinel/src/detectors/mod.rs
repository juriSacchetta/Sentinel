use sentinel_common::EventHeader;

use crate::core::SharedTracker;

mod fileless;
mod reflective;

pub use fileless::FilelessDetector;
pub use reflective::ReflectiveLoaderDetector;

pub trait Detector: Send + Sync {
    /// Returns the name of the detector (for logging)
    fn name(&self) -> &str;

    /// Process a raw event buffer.
    /// Returns `true` if this detector handled the event (optional optimization).
    fn on_event(&self, header: &EventHeader, data: &[u8], tracker: &SharedTracker);
}
