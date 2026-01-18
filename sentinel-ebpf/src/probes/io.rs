use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use sentinel_common::{DupEvent, Fd, HookType};

use crate::make_header;

#[tracepoint]
pub fn sys_enter_dup2(ctx: TracePointContext) -> u32 {
    handle_dup(ctx, HookType::Dup)
}

#[tracepoint]
pub fn sys_enter_dup3(ctx: TracePointContext) -> u32 {
    handle_dup(ctx, HookType::Dup)
}

#[inline(always)]
fn handle_dup(ctx: TracePointContext, event_type: HookType) -> u32 {
    let old_fd = unsafe { ctx.read_at::<u64>(16).unwrap_or(0) as Fd };
    let new_fd = unsafe { ctx.read_at::<u64>(24).unwrap_or(0) as Fd };

    let event = DupEvent {
        header: make_header(event_type),
        old_fd,
        new_fd,
    };

    send_event!(&ctx, event);
    0
}
