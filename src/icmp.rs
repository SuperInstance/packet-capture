//! ICMP header parsing and construction.

use crate::header::{compute_checksum, HeaderError};

/// ICMP type field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    DestinationUnreachable,
    EchoRequest,
    TimeExceeded,
    Other(u8),
}

impl From<u8> for IcmpType {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::EchoReply,
            3 => Self::DestinationUnreachable,
            8 => Self::EchoRequest,
            11 => Self::TimeExceeded,
            other => Self::Other(other),
        }
    }
}

/// ICMP code field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpCode {
    Zero,
    Other(u8),
}

impl From<u8> for IcmpCode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Zero,
            other => Self::Other(other),
        }
    }
}

/// ICMP header (8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
    pub code: IcmpCode,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
}

impl Default for IcmpHeader {
    fn default() -> Self {
        IcmpHeader {
            icmp_type: IcmpType::EchoRequest,
            code: IcmpCode::Zero,
            checksum: 0,
            identifier: 0,
            sequence: 0,
        }
    }
}

impl IcmpHeader {
    pub const SIZE: usize = 8;

    /// Parse ICMP header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, HeaderError> {
        if data.len() < Self::SIZE {
            return Err(HeaderError::Truncated);
        }
        Ok(IcmpHeader {
            icmp_type: IcmpType::from(data[0]),
            code: IcmpCode::from(data[1]),
            checksum: u16::from_be_bytes([data[2], data[3]]),
            identifier: u16::from_be_bytes([data[4], data[5]]),
            sequence: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        buf[0] = match self.icmp_type {
            IcmpType::EchoReply => 0,
            IcmpType::DestinationUnreachable => 3,
            IcmpType::EchoRequest => 8,
            IcmpType::TimeExceeded => 11,
            IcmpType::Other(v) => v,
        };
        buf[1] = match self.code {
            IcmpCode::Zero => 0,
            IcmpCode::Other(v) => v,
        };
        buf[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        buf[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        buf
    }

    /// Compute ICMP checksum over the header + payload.
    pub fn compute_checksum(&self, payload: &[u8]) -> u16 {
        let mut data = self.to_bytes();
        // Zero out checksum field for computation
        data[2] = 0;
        data[3] = 0;
        data.extend(payload);
        compute_checksum(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_default() {
        let hdr = IcmpHeader::default();
        assert_eq!(hdr.icmp_type, IcmpType::EchoRequest);
        assert_eq!(hdr.code, IcmpCode::Zero);
    }

    #[test]
    fn test_icmp_parse_roundtrip() {
        let hdr = IcmpHeader {
            icmp_type: IcmpType::EchoRequest,
            code: IcmpCode::Zero,
            checksum: 0,
            identifier: 0x1234,
            sequence: 1,
        };
        let bytes = hdr.to_bytes();
        let parsed = IcmpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.icmp_type, IcmpType::EchoRequest);
        assert_eq!(parsed.identifier, 0x1234);
        assert_eq!(parsed.sequence, 1);
    }

    #[test]
    fn test_icmp_type_conversion() {
        assert_eq!(IcmpType::from(0), IcmpType::EchoReply);
        assert_eq!(IcmpType::from(3), IcmpType::DestinationUnreachable);
        assert_eq!(IcmpType::from(8), IcmpType::EchoRequest);
        assert_eq!(IcmpType::from(11), IcmpType::TimeExceeded);
        assert_eq!(IcmpType::from(99), IcmpType::Other(99));
    }

    #[test]
    fn test_icmp_checksum() {
        let hdr = IcmpHeader {
            icmp_type: IcmpType::EchoRequest,
            code: IcmpCode::Zero,
            checksum: 0,
            identifier: 1,
            sequence: 1,
        };
        let payload = b"ABCDEFGHIJKLMNOPQRSTUVWXABCDEFGHIJKLMNOPQRSTUVWX";
        let cksum = hdr.compute_checksum(payload);
        assert_ne!(cksum, 0);
    }

    #[test]
    fn test_icmp_parse_truncated() {
        let data = [0u8; 4];
        assert_eq!(IcmpHeader::parse(&data), Err(HeaderError::Truncated));
    }
}
