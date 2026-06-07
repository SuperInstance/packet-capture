//! # packet-capture
//!
//! Packet parsing and capture with protocol dissection for TCP/UDP/ICMP headers.
//!
//! This crate provides zero-dependency packet construction, parsing, and
//! checksum validation for common internet protocols.

pub mod packet;
pub mod header;
pub mod tcp;
pub mod udp;
pub mod icmp;

pub use packet::{Packet, PacketBuilder, Protocol};
pub use header::{IpHeader, HeaderError};
pub use tcp::{TcpHeader, TcpFlags};
pub use udp::UdpHeader;
pub use icmp::{IcmpHeader, IcmpType, IcmpCode};
