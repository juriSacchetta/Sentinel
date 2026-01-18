#![no_std]
#![no_main]

use core::{ffi::c_void, mem};

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_perf_event_output,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};
use sentinel_common::{EventHeader, ExecveEvent, HookType, MemfdEvent, MmapEvent, SocketEvent};

macro_rules! log {
    ($hook:expr, $msg:literal) => {
        aya_ebpf::bpf_printk!(
            b"%s: %s\0",
            $hook.as_bytes().as_ptr(),
            concat!($msg, "\0").as_bytes().as_ptr()
        );
    };
    ($hook:expr, $label:literal, $v1:expr) => {
        unsafe {
            aya_ebpf::bpf_printk!(
                b"%s: %s: %d\0",
                $hook.as_bytes().as_ptr(),
                concat!($label, "\0").as_bytes().as_ptr(),
                $v1
            );
        }
    };
}
// 1. The Stash (Saved in Kernel Map)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemfdState {
    pub filename: [u8; 256],
}

// Default is needed for map retrieval safety
impl Default for MemfdState {
    fn default() -> Self {
        Self { filename: [0; 256] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct SocketState {
    pub domain: u32,
    pub type_: u32,
    pub protocol: u32,
}

#[map]
static EVENTS: PerfEventArray<EventHeader> = PerfEventArray::new(0);

#[map]
static SOCKET_STASH: HashMap<u32, SocketState> = HashMap::with_max_entries(1024, 0);

#[map]
static MEMFD_STASH: HashMap<u32, MemfdState> = HashMap::with_max_entries(1024, 0);

macro_rules! send_event {
    ($ctx:expr, $event:expr) => {
        unsafe {
            let size = mem::size_of_val(&$event) as u64;
            let flags = bpf_get_smp_processor_id() as u64;

            bpf_perf_event_output(
                $ctx.as_ptr(),                      // Context
                &EVENTS as *const _ as *mut c_void, // Map Pointer
                flags,                              // Flags (Current CPU)
                &$event as *const _ as *mut c_void, // Data Pointer
                size,                               // Data Size
            );
        }
    };
}

#[inline(always)]
fn get_pid_tid() -> (u32, u32) {
    // bpf_get_current_pid_tgid() returns:
    // Upper 32 bits: TGID (Process ID in userspace terms)
    // Lower 32 bits: TID  (Thread ID)
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as u32;
    let pid = (pid_tgid >> 32) as u32;
    (pid, tid)
}

#[inline(always)]
fn make_header(event_type: HookType) -> EventHeader {
    let (pid, tid) = get_pid_tid();
    EventHeader {
        event_type,
        pid,
        tid,
    }
}

#[tracepoint]
pub fn memfd_create(ctx: TracePointContext) -> u32 {
    let (_, tid) = get_pid_tid();
    let mut state = MemfdState::default();

    let name_addr: u64 = unsafe {
        match ctx.read_at(16) {
            Ok(ptr) => ptr,
            Err(_) => {
                log!(HookType::Memfd, "Failed to read name pointer");
                return 0;
            }
        }
    };

    let name_ptr = name_addr as *const u8;
    unsafe {
        if bpf_probe_read_user_str_bytes(name_ptr, &mut state.filename).is_err() {
            log!(HookType::Memfd, "Failed to read filename string");
            return 0;
        }
    }

    let _ = MEMFD_STASH.insert(&tid, &state, 0);
    0
}

#[tracepoint]
pub fn memfd_exit(ctx: TracePointContext) -> u32 {
    let (_, tid) = get_pid_tid();
    if let Some(state_ptr) = unsafe { MEMFD_STASH.get(&tid) } {
        let ret: i64 = unsafe { ctx.read_at(16).unwrap_or(-1) };

        if ret >= 0 {
            let state = *state_ptr;
            let event = MemfdEvent {
                header: make_header(HookType::Memfd),
                fd: ret as u32,
                filename: state.filename,
            };

            send_event!(ctx, event);
        }

        let _ = MEMFD_STASH.remove(&tid);
    }

    0
}

#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    let fd = unsafe {
        match ctx.read_at::<i64>(16) {
            Ok(val) => val as u32,
            Err(_) => return 0,
        }
    };

    let flags = unsafe {
        match ctx.read_at::<i64>(48) {
            Ok(val) => val as u32,
            Err(_) => return 0,
        }
    };

    let event = ExecveEvent {
        header: make_header(HookType::Execve),
        fd,
        flags,
    };

    send_event!(ctx, event);
    0
}

#[tracepoint]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    let prot = unsafe { ctx.read_at::<u64>(32).unwrap_or(0) as u32 };
    let fd = unsafe { ctx.read_at::<u64>(48).unwrap_or(0) as u32 };

    let event = MmapEvent {
        header: make_header(HookType::Mmap),
        fd,
        prot,
        flags: 0, // We can skip others to save bandwidth
    };

    send_event!(ctx, event);
    0
}

#[tracepoint]
pub fn sys_enter_socket(ctx: TracePointContext) -> u32 {
    let (_, tid) = get_pid_tid();

    let domain = unsafe { ctx.read_at::<i64>(16).unwrap_or(0) as u32 };
    let type_ = unsafe { ctx.read_at::<i64>(24).unwrap_or(0) as u32 };
    let protocol = unsafe { ctx.read_at::<i64>(32).unwrap_or(0) as u32 };

    let state = SocketState {
        domain,
        type_,
        protocol,
    };

    let _ = SOCKET_STASH.insert(&tid, &state, 0);
    0
}

#[tracepoint]
pub fn sys_exit_socket(ctx: TracePointContext) -> u32 {
    let (_, tid) = get_pid_tid();

    if let Some(state_ptr) = unsafe { SOCKET_STASH.get(&tid) } {
        let ret = unsafe { ctx.read_at::<i64>(16).unwrap_or(-1) };

        if ret >= 0 {
            let state = *state_ptr;
            let event = SocketEvent {
                header: make_header(HookType::Socket),
                fd: ret as u32,
                domain: state.domain,
                type_: state.type_,
                protocol: state.protocol,
            };
            send_event!(ctx, event);
        }
        let _ = SOCKET_STASH.remove(&tid);
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
