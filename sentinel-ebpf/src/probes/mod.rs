use aya_ebpf::{macros::map, maps::PerfEventArray};
use sentinel_common::EventHeader;

mod io;
mod memory;
mod process;
mod socket;

#[map]
pub static EVENTS: PerfEventArray<EventHeader> = PerfEventArray::new(0);
