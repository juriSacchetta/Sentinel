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
