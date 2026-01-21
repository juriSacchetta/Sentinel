#![no_std]

use core::ffi::{c_int, c_uint};

pub type Pid = c_int;
pub type Fd = c_int;
pub type Tid = c_int;
pub type KFlag = c_uint;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum HookType {
    #[default]
    Unknown,
    Memfd,
    Execve,
    Mmap,
    SocketAlloc,
    SocketConnect,
    Dup,
}

impl HookType {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            HookType::Unknown => b"UNKNOWN\0",
            HookType::Memfd => b"MEMFD: \0",
            HookType::Execve => b"EXECVE\0",
            HookType::Mmap => b"MMAP\0",
            HookType::SocketAlloc => b"SOCK_ALLOC\0",
            HookType::SocketConnect => b"SOCK_CONNECT\0",
            HookType::Dup => b"DUP\0",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EventHeader {
    pub event_type: HookType,
    pub pid: Pid,
    pub tid: Tid,
}

/// Event sent when memfd_create completes successfully.
/// Filename buffer is 64 bytes - memfd names are typically short.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemfdEvent {
    pub header: EventHeader,
    pub filename: [u8; 64],
    pub fd: Fd,
}

impl Default for MemfdEvent {
    fn default() -> Self {
        Self {
            header: EventHeader::default(),
            filename: [0; 64],
            fd: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecveEvent {
    pub header: EventHeader,
    pub fd: Fd,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MmapEvent {
    pub header: EventHeader,
    pub fd: Fd,
    pub prot: u32,  // Protection flags (Read/Write/Exec)
    pub flags: u32, // Map flags (Shared/Private)
}

#[repr(C)]
pub struct SocketAllocEvent {
    pub header: EventHeader,
    pub fd: Fd,
    pub domain: u32,
    pub type_: u32,
    pub protocol: u32,
}

#[repr(C)]
pub struct SocketConnectEvent {
    pub header: EventHeader,
    pub fd: Fd,
    pub ip: u32,
    pub port: u16,
    /// 0 = IPv4, 1 = IPv6. Using u8 instead of bool for stable ABI in repr(C).
    pub is_ipv6: u8,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DupEvent {
    pub header: EventHeader,
    pub old_fd: Fd,
    pub new_fd: Fd,
}
