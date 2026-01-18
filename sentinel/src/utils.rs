use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use log::warn;
use sentinel_common::SocketConnectEvent;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketDomain {
    Ipv4,
    Ipv6,
    Unix,
    Netlink,
    Packet,
    Unknown(u32),
}

impl From<u32> for SocketDomain {
    fn from(val: u32) -> Self {
        // Cast to i32 because libc constants are often i32
        match val as i32 {
            libc::AF_INET => SocketDomain::Ipv4,
            libc::AF_INET6 => SocketDomain::Ipv6,
            libc::AF_UNIX => SocketDomain::Unix,
            libc::AF_NETLINK => SocketDomain::Netlink,
            libc::AF_PACKET => SocketDomain::Packet,
            _ => SocketDomain::Unknown(val),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SocketType {
    Stream,
    Dgram,
    Raw,
    SeqPacket,
    Unknown(u32),
}

impl From<u32> for SocketType {
    fn from(val: u32) -> Self {
        // Mask out flags like SOCK_NONBLOCK or SOCK_CLOEXEC to get the base type
        let base_type = (val as i32) & 0xF;

        match base_type {
            libc::SOCK_STREAM => SocketType::Stream,
            libc::SOCK_DGRAM => SocketType::Dgram,
            libc::SOCK_RAW => SocketType::Raw,
            libc::SOCK_SEQPACKET => SocketType::SeqPacket,
            _ => SocketType::Unknown(val),
        }
    }
}

/// Extension trait to add functionality to the shared Event struct
/// ONLY within the userspace context.
pub trait SocketEventExt {
    fn to_socket_addr(&self) -> Option<SocketAddr>;
}
impl SocketEventExt for SocketConnectEvent {
    fn to_socket_addr(&self) -> Option<SocketAddr> {
        // 1. Convert Port (Big Endian -> Native)
        let port = u16::from_be(self.port);

        // 2. Convert IP (u32 -> Ipv4Addr)
        // Note: The kernel stores IPv4 as Big Endian in the struct.
        let ip = Ipv4Addr::from(self.ip.to_be());

        // 3. Construct SocketAddr
        // Note: Currently implementing IPv4 only as per your struct definition
        if self.is_ipv6 {
            warn!("IPv6 address conversion not implemented");
            None
        } else {
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
    }
}
