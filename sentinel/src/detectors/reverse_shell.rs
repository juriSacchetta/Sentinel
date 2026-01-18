use std::mem;

use log::{debug, warn};
use sentinel_common::{DupEvent, EventHeader, HookType, SocketAllocEvent, SocketConnectEvent};

use crate::{
    core::{DescriptorType, ProcessRegistry},
    detectors::Detector,
    utils::SocketEventExt,
};

pub struct ReverseShellDetector;

impl Detector for ReverseShellDetector {
    fn name(&self) -> &str {
        "ReverseShellDetector"
    }

    fn on_event(&self, header: &EventHeader, data: &[u8], registry: &ProcessRegistry) {
        let ptr = data.as_ptr();

        match header.event_type {
            HookType::SocketAlloc => {
                if data.len() < mem::size_of::<SocketAllocEvent>() {
                    return;
                }
                let event = unsafe { (ptr as *const SocketAllocEvent).read_unaligned() };
                let process_lock = registry.get_or_create(header.pid);
                let mut process = process_lock.lock().unwrap();
                process.fds.insert(event.fd, event.into());
            }
            HookType::SocketConnect => {
                if data.len() < mem::size_of::<SocketConnectEvent>() {
                    return;
                }
                let event = unsafe { (ptr as *const SocketConnectEvent).read_unaligned() };
                let process_lock = registry.get_or_create(header.pid);
                let mut process = process_lock.lock().unwrap();

                process.fds.entry(event.fd).and_modify(|desc_type| {
                    if let DescriptorType::Socket {
                        domain: _,
                        type_: _,
                        protocol: _,
                        remote_addr,
                    } = desc_type
                    {
                        *remote_addr = event.to_socket_addr();
                    }
                });
            }
            HookType::Dup => {
                if data.len() < mem::size_of::<DupEvent>() {
                    return;
                }
                let event = unsafe { (ptr as *const DupEvent).read_unaligned() };

                let process_lock = registry.get_or_create(header.pid);
                let mut process = process_lock.lock().unwrap();

                let old_desc = process.fds.get(&event.old_fd).cloned();
                if let Some(DescriptorType::Socket {
                    domain,
                    type_,
                    protocol,
                    remote_addr,
                }) = old_desc
                {
                    // Update the Registry: new_fd is now also that Socket
                    process.fds.insert(
                        event.new_fd,
                        DescriptorType::Socket {
                            domain,
                            type_,
                            protocol,
                            remote_addr,
                        },
                    );

                    // If a Socket is duplicated to STDIN(0), STDOUT(1), or STDERR(2)
                    if event.new_fd <= 2 {
                        let remote_str = remote_addr
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "Unknown".to_string());

                        warn!(
                            "🚨 REVERSE SHELL DETECTED! PID: {} redirected Socket (FD {}) to STDIO (FD {}) -> Remote: {}",
                            header.pid, event.old_fd, event.new_fd, remote_str
                        );
                    } else {
                        debug!(
                            "Socket duped: PID {} moved FD {} -> FD {}",
                            header.pid, event.old_fd, event.new_fd
                        );
                    }
                }
            }
            _ => {}
        }
    }
}
