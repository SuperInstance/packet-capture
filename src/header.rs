//! IP header parsing and error types.

/// Errors that can occur during header parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// Packet is too short.
    Truncated,
    /// Unsupported protocol number.
    UnsupportedProtocol(u8),
    /// Invalid header length.
    InvalidHeaderLength(u8),
    /// Checksum mismatch.
    ChecksumMismatch { expected: u16, got: u16 },
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "packet truncated"),
            Self::UnsupportedProtocol(p) => write!(f, "unsupported protocol: {p}"),
            Self::InvalidHeaderLength(len) => write!(f, "invalid header length: {len}"),
            Self::ChecksumMismatch { expected, got } => {
                write!(f, "checksum mismatch: expected {expected:#06x}, got {got:#06x}")
            }
        }
    }
}

impl std::error::Error for HeaderError {}

/// IPv4 header representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpHeader {
    pub version: u8,
    pub ihl: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: [u8; 4],
    pub dst_addr: [u8; 4],
}

impl IpHeader {
    /// Header length in bytes (IHL * 4).
    pub fn header_len(&self) -> usize {
        (self.ihl as usize) * 4
    }

    /// Parse an IPv4 header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, HeaderError> {
        if data.len() < 20 {
            return Err(HeaderError::Truncated);
        }
        let version = data[0] >> 4;
        if version != 4 {
            return Err(HeaderError::Truncated);
        }
        let ihl = data[0] & 0x0F;
        if ihl < 5 {
            return Err(HeaderError::InvalidHeaderLength(ihl));
        }
        let header_bytes = (ihl as usize) * 4;
        if data.len() < header_bytes {
            return Err(HeaderError::Truncated);
        }
        Ok(IpHeader {
            version,
            ihl,
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: data[6] >> 5,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1F, data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_addr: [data[12], data[13], data[14], data[15]],
            dst_addr: [data[16], data[17], data[18], data[19]],
        })
    }

    /// Serialize the header to bytes, computing the checksum.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.header_len()];
        buf[0] = (self.version << 4) | self.ihl;
        buf[1] = 0; // DSCP/ECN
        buf[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let fo = ((self.flags as u16) << 13) | (self.fragment_offset & 0x1FFF);
        buf[6..8].copy_from_slice(&fo.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        // checksum at [10..12] initially 0
        buf[12..16].copy_from_slice(&self.src_addr);
        buf[16..20].copy_from_slice(&self.dst_addr);
        let cksum = compute_checksum(&buf[..self.header_len()]);
        buf[10..12].copy_from_slice(&cksum.to_be_bytes());
        buf
    }
}

/// Compute the Internet checksum (ones' complement sum).
pub fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Verify a checksum over the given data.
pub fn verify_checksum(data: &[u8], expected: u16) -> bool {
    compute_checksum(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_header_parse_valid() {
        let mut data = vec![0u8; 20];
        data[0] = 0x45; // version 4, IHL 5
        data[2] = 0; // total length high byte
        data[3] = 40; // total length low byte
        data[8] = 64; // TTL
        data[9] = 6; // TCP
        data[12..16].copy_from_slice(&[192, 168, 1, 1]);
        data[16..20].copy_from_slice(&[192, 168, 1, 2]);
        let hdr = IpHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.ihl, 5);
        assert_eq!(hdr.ttl, 64);
        assert_eq!(hdr.protocol, 6);
        assert_eq!(hdr.src_addr, [192, 168, 1, 1]);
        assert_eq!(hdr.dst_addr, [192, 168, 1, 2]);
    }

    #[test]
    fn test_ip_header_parse_truncated() {
        let data = [0u8; 10];
        assert_eq!(IpHeader::parse(&data), Err(HeaderError::Truncated));
    }

    #[test]
    fn test_ip_header_invalid_ihl() {
        let mut data = vec![0u8; 20];
        data[0] = 0x42; // version 4, IHL 2 (invalid)
        let result = IpHeader::parse(&data);
        assert!(matches!(result, Err(HeaderError::InvalidHeaderLength(2))));
    }

    #[test]
    fn test_compute_checksum_empty() {
        assert_eq!(compute_checksum(&[]), 0xFFFF);
    }

    #[test]
    fn test_verify_checksum_roundtrip() {
        let data = [0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                    0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01,
                    0xC0, 0xA8, 0x01, 0x02];
        let cksum = compute_checksum(&data);
        // Set the checksum in bytes 10-11 and recompute
        let mut with_cksum = data;
        with_cksum[10..12].copy_from_slice(&cksum.to_be_bytes());
        // Recomputing over the data with the checksum embedded should give 0
        assert_eq!(compute_checksum(&with_cksum), 0);
    }

    #[test]
    fn test_header_len() {
        let hdr = IpHeader {
            version: 4, ihl: 5, total_length: 40, identification: 0,
            flags: 0, fragment_offset: 0, ttl: 64, protocol: 6,
            checksum: 0, src_addr: [0; 4], dst_addr: [0; 4],
        };
        assert_eq!(hdr.header_len(), 20);
    }

    #[test]
    fn test_to_bytes_roundtrip() {
        let hdr = IpHeader {
            version: 4, ihl: 5, total_length: 40, identification: 0x1234,
            flags: 0, fragment_offset: 0, ttl: 64, protocol: 6,
            checksum: 0, src_addr: [10, 0, 0, 1], dst_addr: [10, 0, 0, 2],
        };
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 20);
        let parsed = IpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.ttl, 64);
        assert_eq!(parsed.src_addr, [10, 0, 0, 1]);
        assert_eq!(parsed.dst_addr, [10, 0, 0, 2]);
    }
}
