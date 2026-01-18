#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use sentinel_common::{EventHeader, HookType, Pid, Tid};

mod macros;
mod probes;

#[inline(always)]
pub fn get_pid_tid() -> (Pid, Tid) {
    // bpf_get_current_pid_tgid() returns:
    // Upper 32 bits: TGID (Process ID in userspace terms)
    // Lower 32 bits: TID  (Thread ID)
    let pid_tgid = bpf_get_current_pid_tgid();
    let tid = pid_tgid as Tid;
    let pid = (pid_tgid >> 32) as Pid;
    (pid, tid)
}

#[inline(always)]
pub fn make_header(event_type: HookType) -> EventHeader {
    let (pid, tid) = get_pid_tid();
    EventHeader {
        event_type,
        pid,
        tid,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
