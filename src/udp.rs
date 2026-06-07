//! UDP header parsing and construction.

use crate::header::{compute_checksum, HeaderError};

/// UDP header (8 bytes fixed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl Default for UdpHeader {
    fn default() -> Self {
        UdpHeader {
            src_port: 0,
            dst_port: 0,
            length: Self::SIZE as u16,
            checksum: 0,
        }
    }
}

impl UdpHeader {
    pub const SIZE: usize = 8;

    /// Parse a UDP header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, HeaderError> {
        if data.len() < Self::SIZE {
            return Err(HeaderError::Truncated);
        }
        Ok(UdpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..6].copy_from_slice(&self.length.to_be_bytes());
        buf[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        buf
    }

    /// Compute UDP checksum with pseudo-header.
    pub fn compute_checksum(&self, src_ip: &[u8; 4], dst_ip: &[u8; 4], payload: &[u8]) -> u16 {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.push(0);
        pseudo.push(17); // UDP protocol
        pseudo.extend_from_slice(&self.length.to_be_bytes());
        pseudo.extend(self.to_bytes());
        pseudo.extend(payload);
        compute_checksum(&pseudo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_default() {
        let hdr = UdpHeader::default();
        assert_eq!(hdr.length, 8);
    }

    #[test]
    fn test_udp_parse_roundtrip() {
        let hdr = UdpHeader {
            src_port: 53,
            dst_port: 12345,
            length: 100,
            checksum: 0xABCD,
        };
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 8);
        let parsed = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.src_port, 53);
        assert_eq!(parsed.dst_port, 12345);
        assert_eq!(parsed.length, 100);
        assert_eq!(parsed.checksum, 0xABCD);
    }

    #[test]
    fn test_udp_parse_truncated() {
        let data = [0u8; 4];
        assert_eq!(UdpHeader::parse(&data), Err(HeaderError::Truncated));
    }

    #[test]
    fn test_udp_checksum() {
        let hdr = UdpHeader {
            src_port: 53,
            dst_port: 9999,
            length: 28,
            checksum: 0,
        };
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let payload = b"hello world test";
        let cksum = hdr.compute_checksum(&src, &dst, payload);
        assert_ne!(cksum, 0);
    }
}
