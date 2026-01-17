#![no_std]

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum HookType {
    #[default]
    Unknown = 0,
    MemfdCreate = 1,
    MemfdExit = 2,
    Execve = 3,
    Mmap = 4,
}

impl HookType {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            HookType::Unknown => b"UNKNOWN\0",
            HookType::MemfdCreate => b"MEMFD_CREATE\0",
            HookType::MemfdExit => b"MEMFD_EXIT\0",
            HookType::Execve => b"EXECVE\0",
            HookType::Mmap => b"MMAP\0",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EventHeader {
    pub event_type: HookType,
    pub pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemfdEnterEvent {
    pub header: EventHeader,
    pub filename: [u8; 256],
}

impl Default for MemfdEnterEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MemfdExitEvent {
    pub header: EventHeader,
    pub fd: u32,
    pub ret: i64,
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
