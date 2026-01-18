use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use sentinel_common::{HookType, SocketEvent};

use crate::{
    get_pid_tid, make_header,
    maps::{SOCKET_STASH, SocketState},
};

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
