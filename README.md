# packet-capture

Packet parsing and capture with protocol dissection for TCP/UDP/ICMP headers.

A zero-dependency Rust library for constructing, parsing, and validating network packets. Supports IPv4 headers, TCP, UDP, and ICMP protocol dissection with Internet checksum computation.

## Features

- **IPv4 header** parsing and serialization with checksum validation
- **TCP header** with flags, sequence numbers, and pseudo-header checksum
- **UDP header** parsing with length validation and checksum
- **ICMP header** support for Echo Request/Reply, Destination Unreachable, Time Exceeded
- **Packet builder** for constructing packets programmatically
- **Internet checksum** computation and verification
- Zero external dependencies — pure `std`

## Usage

```rust
use packet_capture::{PacketBuilder, IpHeader, Protocol, TcpHeader, TcpFlags};

let ip = IpHeader {
    version: 4, ihl: 5, total_length: 40, identification: 0,
    flags: 0, fragment_offset: 0, ttl: 64, protocol: 6,
    checksum: 0, src_addr: [10, 0, 0, 1], dst_addr: [10, 0, 0, 2],
};
let packet = PacketBuilder::new(ip, Protocol::Tcp)
    .payload(vec![1, 2, 3])
    .build();
```

## License

MIT OR Apache-2.0
