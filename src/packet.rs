//! Packet representation and construction.

use crate::header::IpHeader;
use crate::icmp::IcmpHeader;
use crate::tcp::TcpHeader;
use crate::udp::UdpHeader;

/// Supported network protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

/// A captured/parsed network packet.
#[derive(Debug, Clone)]
pub struct Packet {
    pub ip_header: IpHeader,
    pub protocol: Protocol,
    pub payload: Vec<u8>,
    pub tcp_header: Option<TcpHeader>,
    pub udp_header: Option<UdpHeader>,
    pub icmp_header: Option<IcmpHeader>,
}

impl Packet {
    /// Total wire size of this packet in bytes.
    pub fn total_len(&self) -> usize {
        let ip = self.ip_header.header_len();
        let transport = match self.protocol {
            Protocol::Tcp => self.tcp_header.as_ref().map_or(0, |h| h.header_len()),
            Protocol::Udp => UdpHeader::SIZE,
            Protocol::Icmp => IcmpHeader::SIZE,
        };
        ip + transport + self.payload.len()
    }

    /// Parse a raw byte slice into a Packet.
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::header::HeaderError> {
        let ip_header = IpHeader::parse(data)?;
        let offset = ip_header.header_len();
        if data.len() < offset {
            return Err(crate::header::HeaderError::Truncated);
        }
        let proto = match ip_header.protocol {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            other => {
                return Err(crate::header::HeaderError::UnsupportedProtocol(other));
            }
        };
        let rest = &data[offset..];
        let (tcp_header, udp_header, icmp_header, payload_offset) = match proto {
            Protocol::Tcp => {
                let hdr = TcpHeader::parse(rest)?;
                let off = hdr.header_len();
                (Some(hdr), None, None, off)
            }
            Protocol::Udp => {
                let hdr = UdpHeader::parse(rest)?;
                (None, Some(hdr), None, UdpHeader::SIZE)
            }
            Protocol::Icmp => {
                let hdr = IcmpHeader::parse(rest)?;
                (None, None, Some(hdr), IcmpHeader::SIZE)
            }
        };
        let payload = if rest.len() > payload_offset {
            rest[payload_offset..].to_vec()
        } else {
            Vec::new()
        };
        Ok(Packet {
            ip_header,
            protocol: proto,
            payload,
            tcp_header,
            udp_header,
            icmp_header,
        })
    }
}

/// Builder for constructing packets.
#[derive(Debug)]
pub struct PacketBuilder {
    ip_header: IpHeader,
    protocol: Protocol,
    payload: Vec<u8>,
}

impl PacketBuilder {
    pub fn new(ip_header: IpHeader, protocol: Protocol) -> Self {
        Self {
            ip_header,
            protocol,
            payload: Vec::new(),
        }
    }

    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Build the packet (does not serialize to bytes; use the struct directly).
    pub fn build(self) -> Packet {
        let tcp_header = if self.protocol == Protocol::Tcp {
            Some(TcpHeader::default())
        } else {
            None
        };
        let udp_header = if self.protocol == Protocol::Udp {
            Some(UdpHeader::default())
        } else {
            None
        };
        let icmp_header = if self.protocol == Protocol::Icmp {
            Some(IcmpHeader::default())
        } else {
            None
        };
        Packet {
            ip_header: self.ip_header,
            protocol: self.protocol,
            payload: self.payload,
            tcp_header,
            udp_header,
            icmp_header,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::IpHeader;

    fn sample_ip_header() -> IpHeader {
        IpHeader {
            version: 4,
            ihl: 5,
            total_length: 40,
            identification: 0x1234,
            flags: 0,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6,
            checksum: 0,
            src_addr: [192, 168, 1, 1],
            dst_addr: [192, 168, 1, 2],
        }
    }

    #[test]
    fn test_packet_builder_tcp() {
        let pkt = PacketBuilder::new(sample_ip_header(), Protocol::Tcp)
            .payload(vec![1, 2, 3])
            .build();
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert!(pkt.tcp_header.is_some());
        assert_eq!(pkt.payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_packet_builder_udp() {
        let mut ip = sample_ip_header();
        ip.protocol = 17;
        let pkt = PacketBuilder::new(ip, Protocol::Udp).build();
        assert_eq!(pkt.protocol, Protocol::Udp);
        assert!(pkt.udp_header.is_some());
    }

    #[test]
    fn test_packet_builder_icmp() {
        let mut ip = sample_ip_header();
        ip.protocol = 1;
        let pkt = PacketBuilder::new(ip, Protocol::Icmp).build();
        assert_eq!(pkt.protocol, Protocol::Icmp);
        assert!(pkt.icmp_header.is_some());
    }

    #[test]
    fn test_total_len_tcp() {
        let pkt = PacketBuilder::new(sample_ip_header(), Protocol::Tcp)
            .payload(vec![0; 20])
            .build();
        // IP header (20) + TCP header (20) + payload (20) = 60
        assert_eq!(pkt.total_len(), 60);
    }

    #[test]
    fn test_total_len_udp() {
        let mut ip = sample_ip_header();
        ip.protocol = 17;
        let pkt = PacketBuilder::new(ip, Protocol::Udp)
            .payload(vec![0; 10])
            .build();
        // IP (20) + UDP (8) + payload (10) = 38
        assert_eq!(pkt.total_len(), 38);
    }
}
