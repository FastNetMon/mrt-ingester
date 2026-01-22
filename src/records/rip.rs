// SPDX-License-Identifier: MIT OR Apache-2.0

//! RIP and RIPng protocol MRT record parsing.
//!
//! This module handles both RIP (IPv4) and RIPng (IPv6) routing protocol records.

use crate::address::{read_ipv4, read_ipv6};
use crate::Header;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

/// RIP (Routing Information Protocol) record for IPv4.
///
/// Contains the source and destination addresses along with the RIP message.
#[derive(Debug, Clone)]
pub struct RIP {
    /// Remote peer IPv4 address
    pub remote: Ipv4Addr,
    /// Local IPv4 address
    pub local: Ipv4Addr,
    /// Raw RIP message bytes
    pub message: Vec<u8>,
}

impl RIP {
    /// Parse a RIP record from the stream.
    ///
    /// # Arguments
    ///
    /// * `header` - The MRT record header
    /// * `stream` - The input stream positioned at the record body
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        let remote = read_ipv4(stream)?;
        let local = read_ipv4(stream)?;

        // Calculate message length: total length minus two IPv4 addresses (8 bytes)
        let message_len = header.length.saturating_sub(8) as usize;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message)?;

        Ok(RIP {
            remote,
            local,
            message,
        })
    }
}

/// RIPng (RIP next generation) record for IPv6.
///
/// Contains the source and destination addresses along with the RIPng message.
#[derive(Debug, Clone)]
pub struct RIPNG {
    /// Remote peer IPv6 address
    pub remote: Ipv6Addr,
    /// Local IPv6 address
    pub local: Ipv6Addr,
    /// Raw RIPng message bytes
    pub message: Vec<u8>,
}

impl RIPNG {
    /// Parse a RIPNG record from the stream.
    ///
    /// # Arguments
    ///
    /// * `header` - The MRT record header
    /// * `stream` - The input stream positioned at the record body
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        let remote = read_ipv6(stream)?;
        let local = read_ipv6(stream)?;

        // Calculate message length: total length minus two IPv6 addresses (32 bytes)
        let message_len = header.length.saturating_sub(32) as usize;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message)?;

        Ok(RIPNG {
            remote,
            local,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rip() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 6,
            sub_type: 0,
            length: 12, // 4 + 4 + 4 bytes message
        };
        let data: &[u8] = &[
            192, 168, 1, 1, // remote
            192, 168, 1, 2, // local
            0x01, 0x02, 0x03, 0x04, // message
        ];
        let result = RIP::parse(&header, &mut data.as_ref()).unwrap();
        assert_eq!(result.remote, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(result.local, Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(result.message, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_parse_ripng() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 8,
            sub_type: 0,
            length: 36, // 16 + 16 + 4 bytes message
        };
        let mut data = Vec::new();
        // remote: 2001:db8::1
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // local: 2001:db8::2
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // message
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let result = RIPNG::parse(&header, &mut data.as_slice()).unwrap();
        assert_eq!(
            result.remote,
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(result.local, "2001:db8::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(result.message, vec![0x01, 0x02, 0x03, 0x04]);
    }
}
