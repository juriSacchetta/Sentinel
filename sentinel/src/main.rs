mod bus;
mod core;
mod detectors;
mod utils;

use std::sync::Arc;

use aya::{maps::perf::PerfEventArray, programs::TracePoint, util::online_cpus};
use bytes::BytesMut;
use log::{debug, info, warn};
use tokio::{io::unix::AsyncFd, signal};

use crate::{
    bus::EventBus,
    core::ProcessRegistry,
    detectors::{FilelessDetector, ReflectiveLoaderDetector},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

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

    let registry = ProcessRegistry::new();

    // 3. Setup Event Bus & Register Detectors
    //    Ideally, wrap EventBus in Arc so it can be shared across async tasks
    let mut bus = EventBus::new(registry);
    bus.register(FilelessDetector);
    bus.register(ReflectiveLoaderDetector);
    // Future: bus.register(ReverseShellDetector);

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

    let shared_bus = Arc::new(bus);

    for cpu_id in online_cpus().unwrap() {
        let buf = events.open(cpu_id, None)?;
        let bus_clone = shared_bus.clone();

        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            let mut async_buf = AsyncFd::new(buf).unwrap();

            loop {
                let mut guard = async_buf.readable_mut().await.unwrap();
                let events_read = guard.get_inner_mut().read_events(&mut buffers).unwrap();
                if events_read.lost > 0 {
                    warn!("⚠️  DROPPED {} EVENTS! We are too slow!", events_read.lost);
                }
                guard.clear_ready();

                for bytes in buffers.iter_mut().take(events_read.read) {
                    bus_clone.process_packet(bytes);
                }
            }
        });
    }

    info!("Sentinel is watching (AsyncFd Mode). Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
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

    let tracepoint: &mut TracePoint = match program.try_into() {
        Ok(tp) => tp,
        Err(e) => {
            warn!("Program '{}' is not a TracePoint: {}", prog_name, e);
            return;
        }
    };

    match tracepoint.load() {
        Ok(_) => debug!("Loaded program '{}'", prog_name),
        Err(e) => {
            warn!("Failed to load program '{}': {}", prog_name, e);
            return;
        }
    }

    match tracepoint.attach(category, event_name) {
        Ok(_) => info!("Attached '{}' to {}/{}", prog_name, category, event_name),
        Err(e) => warn!(
            "Failed to attach '{}' to {}/{}: {}",
            prog_name, category, event_name, e
        ),
    }
}
