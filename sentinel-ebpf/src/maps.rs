use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerfEventArray},
};
use sentinel_common::EventHeader;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemfdState {
    pub filename: [u8; 256],
}

impl Default for MemfdState {
    fn default() -> Self {
        Self { filename: [0; 256] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SocketState {
    pub domain: u32,
    pub type_: u32,
    pub protocol: u32,
}

#[map]
pub static EVENTS: PerfEventArray<EventHeader> = PerfEventArray::new(0);

#[map]
pub static SOCKET_STASH: HashMap<u32, SocketState> = HashMap::with_max_entries(1024, 0);

#[map]
pub static MEMFD_STASH: HashMap<u32, MemfdState> = HashMap::with_max_entries(1024, 0);
