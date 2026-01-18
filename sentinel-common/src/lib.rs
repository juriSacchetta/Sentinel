#![no_std]

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum HookType {
    #[default]
    Unknown,
    Memfd,
    Execve,
    Mmap,
    Socket,
}

impl HookType {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            HookType::Unknown => b"UNKNOWN\0",
            HookType::Memfd => b"MEMFD: \0",
            HookType::Execve => b"EXECVE\0",
            HookType::Mmap => b"MMAP\0",
            HookType::Socket => b"SOCKET\0",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EventHeader {
    pub event_type: HookType,
    pub pid: u32,
    pub tid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemfdEvent {
    pub header: EventHeader,
    pub filename: [u8; 256],
    pub fd: u32,
}

impl Default for MemfdEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; 256],
            fd: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecveEvent {
    pub header: EventHeader,
    pub fd: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MmapEvent {
    pub header: EventHeader,
    pub fd: u32,
    pub prot: u32,  // Protection flags (Read/Write/Exec)
    pub flags: u32, // Map flags (Shared/Private)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SocketEvent {
    pub header: EventHeader,
    pub fd: u32,
    pub domain: u32,
    pub type_: u32,
    pub protocol: u32,
}
