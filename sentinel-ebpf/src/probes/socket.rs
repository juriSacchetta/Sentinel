use aya_ebpf::{
    EbpfContext,
    helpers::generated::bpf_probe_read_user,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use sentinel_common::{Fd, HookType, Pid, SocketAllocEvent, SocketConnectEvent};

use crate::{get_pid_tid, make_header, vmlinux::sockaddr_in};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SocketState {
    pub domain: u32,
    pub type_: u32,
    pub protocol: u32,
}

#[map]
pub static SOCKET_STASH: HashMap<Pid, SocketState> = HashMap::with_max_entries(1024, 0);

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
            let event = SocketAllocEvent {
                header: make_header(HookType::SocketAlloc),
                fd: ret as Fd,
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

// 1. Tracepoint Layout
#[repr(C)]
struct ConnectArgs {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,

    syscall_nr: i32,
    pad: u32,

    fd: u64,
    uservaddr: u64, // Pointer to struct sockaddr
    addrlen: u64,
}

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let args = unsafe {
        let ptr = ctx.as_ptr() as *const ConnectArgs;
        &*ptr
    };

    let fd = args.fd as Fd;
    let sockaddr_ptr = args.uservaddr as *const sockaddr_in; // Use generated type

    if sockaddr_ptr.is_null() {
        return 0;
    }

    let mut sockaddr: sockaddr_in = unsafe { core::mem::zeroed() };

    let ret = unsafe {
        bpf_probe_read_user(
            &mut sockaddr as *mut sockaddr_in as *mut _, // Dest
            core::mem::size_of::<sockaddr_in>() as u32,  // Size (ARG 2)
            sockaddr_ptr as *const _,                    // Src  (ARG 3)
        )
    };

    if ret != 0 {
        return 0;
    }

    if sockaddr.sin_family == 2 {
        let ip = sockaddr.sin_addr.s_addr;
        let port = sockaddr.sin_port;

        let event = SocketConnectEvent {
            header: make_header(HookType::SocketConnect),
            fd,
            ip,
            port,
            is_ipv6: false,
        };

        send_event!(ctx, event);
    }

    0
}
