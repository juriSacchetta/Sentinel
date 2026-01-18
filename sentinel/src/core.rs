use std::{
    collections::HashMap,
    fmt::Display,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use dashmap::DashMap;
use sentinel_common::{Fd, Pid};

use crate::utils::SocketDomain;

#[derive(Debug, Clone)]
pub enum DescriptorType {
    /// Anonymous memory file (Potential Fileless payload)
    Memfd { name: String },
    /// Network connection (Potential Reverse Shell)
    Socket {
        domain: SocketDomain,
        type_: u32,
        protocol: u32,
    },
    /// Regular file on disk (Potential Persistence/Exfiltration)
    File { path: String },
    /// Unknown or untracked
    Unknown,
}

impl Display for DescriptorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DescriptorType::Memfd { name } => write!(f, "Memfd({})", name),
            DescriptorType::Socket {
                domain,
                type_,
                protocol,
            } => {
                write!(
                    f,
                    "Socket(domain: {:?}, type: {}, protocol: {})",
                    domain, type_, protocol
                )
            }
            DescriptorType::File { path } => write!(f, "File({})", path),
            DescriptorType::Unknown => write!(f, "Unknown"),
        }
    }
}

pub struct Process {
    pub pid: Pid,
    pub start_time: SystemTime,

    // Static Info (Cached so we don't hit disk constantly)
    pub binary_path: Option<PathBuf>,
    pub binary_name: Option<String>,

    // Dynamic State: The File Descriptor Table
    // Maps FD (u32) -> The Resource (Socket/Memfd/File)
    pub fds: HashMap<Fd, DescriptorType>,
}

impl Process {
    pub fn new(pid: Pid) -> Self {
        let (path, name) = match resolve_process_info(pid) {
            Some((p, n)) => (Some(p), Some(n)),
            None => (None, None),
        };

        Self {
            pid,
            start_time: SystemTime::now(),
            binary_path: path,
            binary_name: name,
            fds: HashMap::new(),
        }
    }
}

fn resolve_process_info(pid: Pid) -> Option<(PathBuf, String)> {
    let path = PathBuf::from(format!("/proc/{}/exe", pid));

    // Read the symbolic link to get the real binary path
    if let Ok(real_path) = fs::read_link(&path) {
        let name = real_path.file_name()?.to_string_lossy().to_string();

        return Some((real_path, name));
    }
    None
}

pub struct ProcessRegistry {
    // DashMap for concurrent map access + Mutex for individual process access
    processes: DashMap<Pid, Arc<Mutex<Process>>>,
}

impl ProcessRegistry {
    pub fn new() -> Self {
        Self {
            processes: DashMap::new(),
        }
    }

    /// Gets a handle to a process, creating it if it doesn't exist
    pub fn get_or_create(&self, pid: Pid) -> Arc<Mutex<Process>> {
        self.processes
            .entry(pid)
            .or_insert_with(|| Arc::new(Mutex::new(Process::new(pid))))
            .clone()
    }

    /// Remove a process when it exits (Clean up memory)
    pub fn remove(&self, pid: Pid) {
        self.processes.remove(&pid);
    }
}
