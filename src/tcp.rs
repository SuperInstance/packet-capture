//! TCP header parsing and construction.

use crate::header::{compute_checksum, HeaderError};

/// TCP header flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;

    pub fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
}

/// TCP header representation (20 bytes minimum).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl Default for TcpHeader {
    fn default() -> Self {
        TcpHeader {
            src_port: 0,
            dst_port: 0,
            seq_num: 0,
            ack_num: 0,
            data_offset: 5,
            flags: TcpFlags::default(),
            window_size: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
    }
}

impl TcpHeader {
    /// Header length in bytes.
    pub fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    /// Parse a TCP header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, HeaderError> {
        if data.len() < 20 {
            return Err(HeaderError::Truncated);
        }
        let data_offset = (data[12] >> 4) & 0x0F;
        if data_offset < 5 {
            return Err(HeaderError::InvalidHeaderLength(data_offset));
        }
        let needed = (data_offset as usize) * 4;
        if data.len() < needed {
            return Err(HeaderError::Truncated);
        }
        Ok(TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset,
            flags: TcpFlags(data[13]),
            window_size: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.header_len();
        let mut buf = vec![0u8; len];
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        buf[12] = (self.data_offset << 4) & 0xF0;
        buf[13] = self.flags.0;
        buf[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        // checksum at [16..18] — left as-is (caller can compute)
        buf[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        buf[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
        buf
    }

    /// Compute TCP checksum with pseudo-header.
    pub fn compute_checksum(&self, src_ip: &[u8; 4], dst_ip: &[u8; 4], payload: &[u8]) -> u16 {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dst_ip);
        pseudo.push(0); // reserved
        pseudo.push(6); // TCP protocol
        let tcp_len = self.header_len() + payload.len();
        pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo.extend(self.to_bytes());
        pseudo.extend(payload);
        compute_checksum(&pseudo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags(TcpFlags::SYN | TcpFlags::ACK);
        assert!(flags.contains(TcpFlags::SYN));
        assert!(flags.contains(TcpFlags::ACK));
        assert!(!flags.contains(TcpFlags::FIN));
    }

    #[test]
    fn test_tcp_default_header_len() {
        let hdr = TcpHeader::default();
        assert_eq!(hdr.header_len(), 20);
    }

    #[test]
    fn test_tcp_parse_valid() {
        let mut data = vec![0u8; 20];
        data[0] = 0; data[1] = 80; // src port 80
        data[2] = 1; data[3] = 187; // dst port 443
        data[4..8].copy_from_slice(&100u32.to_be_bytes());
        data[8..12].copy_from_slice(&200u32.to_be_bytes());
        data[12] = 0x50; // data offset = 5
        data[13] = TcpFlags::SYN;
        data[14] = 0xFF; data[15] = 0xFF; // window
        let hdr = TcpHeader::parse(&data).unwrap();
        assert_eq!(hdr.src_port, 80);
        assert_eq!(hdr.dst_port, 443);
        assert_eq!(hdr.seq_num, 100);
        assert!(hdr.flags.contains(TcpFlags::SYN));
    }

    #[test]
    fn test_tcp_parse_truncated() {
        let data = [0u8; 10];
        assert_eq!(TcpHeader::parse(&data), Err(HeaderError::Truncated));
    }

    #[test]
    fn test_tcp_to_bytes_roundtrip() {
        let hdr = TcpHeader {
            src_port: 12345,
            dst_port: 80,
            seq_num: 1000,
            ack_num: 2000,
            data_offset: 5,
            flags: TcpFlags(TcpFlags::PSH | TcpFlags::ACK),
            window_size: 32768,
            checksum: 0,
            urgent_ptr: 0,
        };
        let bytes = hdr.to_bytes();
        let parsed = TcpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 80);
        assert_eq!(parsed.seq_num, 1000);
        assert_eq!(parsed.ack_num, 2000);
        assert!(parsed.flags.contains(TcpFlags::PSH));
    }

    #[test]
    fn test_tcp_checksum() {
        let hdr = TcpHeader::default();
        let src = [192, 168, 1, 1];
        let dst = [192, 168, 1, 2];
        let payload = b"hello";
        let cksum = hdr.compute_checksum(&src, &dst, payload);
        assert_ne!(cksum, 0);
    }
}
