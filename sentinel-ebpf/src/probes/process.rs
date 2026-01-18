use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use sentinel_common::{ExecveEvent, Fd, HookType};

use crate::make_header;

#[tracepoint]
pub fn sys_enter_execveat(ctx: TracePointContext) -> u32 {
    let fd = unsafe {
        match ctx.read_at::<i64>(16) {
            Ok(val) => val as Fd,
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
