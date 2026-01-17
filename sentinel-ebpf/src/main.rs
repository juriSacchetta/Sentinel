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
    maps::PerfEventArray,
    programs::TracePointContext,
};
use sentinel_common::{EventHeader, HookType, MemfdEnterEvent, MemfdExitEvent};

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

#[map]
static EVENTS: PerfEventArray<EventHeader> = PerfEventArray::new(0);

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
fn make_header(event_type: HookType) -> EventHeader {
    // bpf_get_current_pid_tgid() returns:
    // Upper 32 bits: TGID (Process ID in userspace terms)
    // Lower 32 bits: TID  (Thread ID)
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    EventHeader { event_type, pid }
}

#[tracepoint]
pub fn memfd_create(ctx: TracePointContext) -> u32 {
    let mut event = MemfdEnterEvent {
        header: make_header(HookType::MemfdCreate),
        filename: [0; 256],
    };

    let name_addr: u64 = unsafe {
        match ctx.read_at(16) {
            Ok(ptr) => ptr,
            Err(_) => {
                log!(HookType::MemfdCreate, "Failed to read name pointer");
                return 0;
            }
        }
    };

    let name_ptr = name_addr as *const u8;
    unsafe {
        if bpf_probe_read_user_str_bytes(name_ptr, &mut event.filename).is_err() {
            log!(HookType::MemfdCreate, "Failed to read filename string");
            return 0;
        }
    }

    send_event!(ctx, event);
    0
}

#[tracepoint]
pub fn memfd_exit(ctx: TracePointContext) -> u32 {
    let mut event = MemfdExitEvent {
        header: make_header(HookType::MemfdExit),
        ret: 0,
        fd: 0,
    };

    let ret: i64 = unsafe {
        match ctx.read_at(16) {
            Ok(val) => val,
            Err(_) => {
                log!(HookType::MemfdExit, "Failed to read return value");
                return 0;
            }
        }
    };

    if ret < 0 {
        // Syscall failed, ignore it
        return 0;
    }

    event.fd = ret as u32;
    event.ret = ret;

    send_event!(ctx, event);

    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
