#![macro_use]

#[macro_export]
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

#[macro_export]
macro_rules! send_event {
    ($ctx:expr, $event:expr) => {
        use core::{ffi::c_void, mem};

        use aya_ebpf::{
            EbpfContext,
            helpers::{bpf_get_smp_processor_id, bpf_perf_event_output},
        };
        use $crate::probes::EVENTS;
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
