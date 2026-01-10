//! OSPF protocol MRT record parsing.
//!
//! This module handles OSPFv2 (IPv4) and OSPFv3 (IPv4/IPv6) routing protocol records.

use crate::address::{read_afi, read_ip_by_afi, read_ipv4};
use crate::Header;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};

/// OSPFv2 protocol record.
///
/// Contains IPv4 addresses for source and destination along with the OSPF message.
#[derive(Debug, Clone)]
pub struct OSPFv2 {
    /// Remote peer IPv4 address
    pub remote: Ipv4Addr,
    /// Local IPv4 address
    pub local: Ipv4Addr,
    /// Raw OSPF message bytes
    pub message: Vec<u8>,
}

impl OSPFv2 {
    /// Parse an OSPFv2 record from the stream.
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

        Ok(OSPFv2 {
            remote,
            local,
            message,
        })
    }
}

/// OSPFv3 protocol record.
///
/// OSPFv3 can use either IPv4 or IPv6 addresses, determined by the AFI field.
#[derive(Debug, Clone)]
pub struct OSPFv3 {
    /// Remote peer IP address (IPv4 or IPv6)
    pub remote: IpAddr,
    /// Local IP address (IPv4 or IPv6)
    pub local: IpAddr,
    /// Raw OSPF message bytes
    pub message: Vec<u8>,
}

impl OSPFv3 {
    /// Parse an OSPFv3 record from the stream.
    ///
    /// OSPFv3 records begin with an AFI field to indicate the address family,
    /// followed by the remote and local addresses and the OSPF message.
    ///
    /// # Arguments
    ///
    /// * `header` - The MRT record header
    /// * `stream` - The input stream positioned at the record body
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        let afi = read_afi(stream)?;
        let remote = read_ip_by_afi(stream, &afi)?;
        let local = read_ip_by_afi(stream, &afi)?;

        // Calculate message length: total minus AFI (2) and addresses
        // For extended types, length already accounts for microseconds being subtracted
        let body_length = if header.record_type == 49 {
            // OSPFv3_ET
            header.length.saturating_sub(4)
        } else {
            header.length
        };

        let addresses_size = afi.size() * 2 + 2; // Two addresses plus AFI field
        let message_len = body_length.saturating_sub(addresses_size) as usize;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message)?;

        Ok(OSPFv3 {
            remote,
            local,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_parse_ospfv2() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 11,
            sub_type: 0,
            length: 12, // 4 + 4 + 4 bytes message
        };
        let data: &[u8] = &[
            10, 0, 0, 1, // remote
            10, 0, 0, 2, // local
            0x01, 0x02, 0x03, 0x04, // message
        ];
        let result = OSPFv2::parse(&header, &mut data.as_ref()).unwrap();
        assert_eq!(result.remote, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(result.local, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(result.message, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_parse_ospfv3_ipv4() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 48,
            sub_type: 0,
            length: 14, // 2 (AFI) + 4 + 4 + 4 bytes message
        };
        let data: &[u8] = &[
            0x00, 0x01, // AFI = IPv4
            10, 0, 0, 1, // remote
            10, 0, 0, 2, // local
            0x01, 0x02, 0x03, 0x04, // message
        ];
        let result = OSPFv3::parse(&header, &mut data.as_ref()).unwrap();
        assert_eq!(result.remote, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(result.local, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(result.message, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_parse_ospfv3_ipv6() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 48,
            sub_type: 0,
            length: 38, // 2 (AFI) + 16 + 16 + 4 bytes message
        };
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x02]); // AFI = IPv6
        // remote: 2001:db8::1
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // local: 2001:db8::2
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // message
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let result = OSPFv3::parse(&header, &mut data.as_slice()).unwrap();
        assert_eq!(
            result.remote,
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(
            result.local,
            IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap())
        );
        assert_eq!(result.message, vec![0x01, 0x02, 0x03, 0x04]);
    }
}
