use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use sentinel_common::{Fd, HookType, MemfdEvent, Pid};

use crate::{get_pid_tid, make_header};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemfdState {
    pub filename: [u8; 256],
}

impl Default for MemfdState {
    fn default() -> Self {
        Self { filename: [0; 256] }
    }
}

#[map]
pub static MEMFD_STASH: HashMap<Pid, MemfdState> = HashMap::with_max_entries(1024, 0);

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
                fd: ret as Fd,
                filename: state.filename,
            };

            send_event!(ctx, event);
        }

        let _ = MEMFD_STASH.remove(&tid);
    }

    0
}
