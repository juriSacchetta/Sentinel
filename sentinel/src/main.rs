pub mod core;
use std::{
    mem,
    sync::{Arc, Mutex},
};

use aya::{
    maps::perf::{PerfEventArray, PerfEventArrayBuffer},
    programs::TracePoint,
    util::online_cpus,
};
use bytes::BytesMut;
use log::{debug, info, warn};
use sentinel_common::{
    EventHeader, ExecveEvent, HookType, MemfdEnterEvent, MemfdExitEvent, MmapEvent,
};
use tokio::{io::unix::AsyncFd, signal};

use crate::core::{SharedTracker, TrackerState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sentinel"
    )))?;

    let tracker = Arc::new(Mutex::new(TrackerState::new()));

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    attach_hook(
        &mut ebpf,
        "memfd_create",
        "syscalls",
        "sys_enter_memfd_create",
    );

    attach_hook(&mut ebpf, "memfd_exit", "syscalls", "sys_exit_memfd_create");

    attach_hook(
        &mut ebpf,
        "sys_enter_execveat",
        "syscalls",
        "sys_enter_execveat",
    );

    attach_hook(&mut ebpf, "sys_enter_mmap", "syscalls", "sys_enter_mmap");

    let mut events = PerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus().unwrap() {
        // Open the buffer for this specific CPU
        let buf = events.open(cpu_id, None)?;

        let tracker_clone = tracker.clone();

        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            let mut async_buf: AsyncFd<PerfEventArrayBuffer<_>> = AsyncFd::new(buf).unwrap();
            loop {
                let mut guard = async_buf.readable_mut().await.unwrap();
                let events_read = guard.get_inner_mut().read_events(&mut buffers).unwrap();
                guard.clear_ready();
                for bytes in buffers.iter_mut().take(events_read.read) {
                    process_packet(bytes, &tracker_clone);
                }
            }
        });
    }

    info!("Sentinel is watching (AsyncFd Mode). Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn process_packet(buf: &[u8], tracker_mutex: &SharedTracker) {
    if buf.len() < mem::size_of::<EventHeader>() {
        return;
    }

    let ptr = buf.as_ptr();
    let header = unsafe { *(ptr as *const EventHeader) };

    match header.event_type {
        HookType::MemfdCreate => {
            if buf.len() >= mem::size_of::<MemfdEnterEvent>() {
                let event = unsafe { (ptr as *const MemfdEnterEvent).read_unaligned() };

                let name = String::from_utf8_lossy(&event.filename)
                    .trim_matches('\0')
                    .to_string();

                {
                    let mut tracker = tracker_mutex.lock().unwrap();
                    tracker.insert_pending(header.pid, name.clone());
                }

                println!(
                    "[ENTER] PID: {:<6} | Asking for File: '{}'",
                    header.pid, name
                );
            }
        }
        HookType::MemfdExit => {
            if buf.len() >= mem::size_of::<MemfdExitEvent>() {
                let event = unsafe { (ptr as *const MemfdExitEvent).read_unaligned() };

                {
                    let mut tracker = tracker_mutex.lock().unwrap();
                    tracker.promote_to_active(header.pid, event.fd);
                }

                println!(
                    "ℹ️  [TRACK] PID {} created memfd FD {}",
                    header.pid, event.fd
                );
                println!("[EXIT]  PID: {:<6} | Created FD: {}", header.pid, event.fd);
            }
        }
        HookType::Execve => {
            if buf.len() >= mem::size_of::<ExecveEvent>() {
                let event = unsafe { (ptr as *const ExecveEvent).read_unaligned() };
                let tracker = tracker_mutex.lock().unwrap();

                if let Some(map) = tracker.get_active(&header.pid)
                    && let Some(name) = map.get(&event.fd)
                {
                    println!("🚨 [ALERT] FILELESS EXECUTION DETECTED!");
                    println!("    PID:   {}", header.pid);
                    println!("    FD:    {}", event.fd);
                    println!("    Name:  {}", name); // NOW SHOWS REAL NAME
                    println!("    Flags: {}", event.flags);
                }
            }
        }
        HookType::Mmap => {
            if buf.len() >= mem::size_of::<MmapEvent>() {
                let event = unsafe { (ptr as *const MmapEvent).read_unaligned() };

                let state = tracker_mutex.lock().unwrap();

                if let Some(map) = state.get_active(&header.pid)
                    && let Some(name) = map.get(&event.fd)
                {
                    let is_executable = (event.prot & (libc::PROT_EXEC as u32)) != 0;
                    if is_executable {
                        println!("🚨 [ALERT] REFLECTIVE CODE LOADING DETECTED!");
                        println!("    PID:    {}", header.pid);
                        println!("    FD:     {} ({})", event.fd, name);
                        println!("    Action: mmap(PROT_EXEC)");
                    }
                }
            }
        }
        _ => {
            warn!("Unknown event type received: {:?}", header.event_type);
        }
    }
}

fn attach_hook(ebpf: &mut aya::Ebpf, prog_name: &str, category: &str, event_name: &str) {
    // 1. Try to find the program by name
    let program = match ebpf.program_mut(prog_name) {
        Some(p) => p,
        None => {
            warn!(
                "eBPF Program '{}' not found. Check your kernel code names.",
                prog_name
            );
            return;
        }
    };

    // 2. Try to interpret it as a TracePoint
    let tracepoint: &mut TracePoint = match program.try_into() {
        Ok(tp) => tp,
        Err(e) => {
            warn!("Program '{}' is not a TracePoint: {}", prog_name, e);
            return;
        }
    };

    // 3. Try to Load
    match tracepoint.load() {
        Ok(_) => debug!("Loaded program '{}'", prog_name),
        Err(e) => {
            warn!("Failed to load program '{}': {}", prog_name, e);
            return;
        }
    }

    // 4. Try to Attach
    match tracepoint.attach(category, event_name) {
        Ok(_) => info!("Attached '{}' to {}/{}", prog_name, category, event_name),
        Err(e) => warn!(
            "Failed to attach '{}' to {}/{}: {}",
            prog_name, category, event_name, e
        ),
    }
}
