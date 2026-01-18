use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use sentinel_common::{EventHeader, ExecveEvent, HookType, MmapEvent};

use crate::make_header;

pub mod memfd;
pub mod socket;

#[map]
pub static EVENTS: PerfEventArray<EventHeader> = PerfEventArray::new(0);

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
