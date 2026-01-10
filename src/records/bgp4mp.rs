//! BGP4MP MRT record parsing (Types 16, 17).
//!
//! This is the modern BGP MRT record format supporting both IPv4 and IPv6 peers,
//! 16-bit and 32-bit AS numbers, and Add-Path extensions.

#![allow(non_camel_case_types)]

use crate::address::{read_afi, read_ip_by_afi, read_prefix};
use crate::Header;
use crate::AFI;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::IpAddr;

/// BGP4MP subtype constants
mod subtypes {
    pub const STATE_CHANGE: u16 = 0;
    pub const MESSAGE: u16 = 1;
    pub const ENTRY: u16 = 2;
    pub const SNAPSHOT: u16 = 3;
    pub const MESSAGE_AS4: u16 = 4;
    pub const STATE_CHANGE_AS4: u16 = 5;
    pub const MESSAGE_LOCAL: u16 = 6;
    pub const MESSAGE_AS4_LOCAL: u16 = 7;
    pub const MESSAGE_ADDPATH: u16 = 8;
    pub const MESSAGE_AS4_ADDPATH: u16 = 9;
    pub const MESSAGE_LOCAL_ADDPATH: u16 = 10;
    pub const MESSAGE_AS4_LOCAL_ADDPATH: u16 = 11;
}

/// BGP4MP record enum.
///
/// The modern MRT format for BGP data, supporting IPv4/IPv6 peers
/// and both 16-bit and 32-bit AS numbers.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum BGP4MP {
    /// BGP state change (16-bit ASN)
    STATE_CHANGE(STATE_CHANGE),
    /// BGP message (16-bit ASN)
    MESSAGE(MESSAGE),
    /// Deprecated RIB entry format
    ENTRY(ENTRY),
    /// Deprecated snapshot pointer
    SNAPSHOT(SNAPSHOT),
    /// BGP message (32-bit ASN)
    MESSAGE_AS4(MESSAGE_AS4),
    /// BGP state change (32-bit ASN)
    STATE_CHANGE_AS4(STATE_CHANGE_AS4),
    /// Local BGP message (16-bit ASN)
    MESSAGE_LOCAL(MESSAGE),
    /// Local BGP message (32-bit ASN)
    MESSAGE_AS4_LOCAL(MESSAGE_AS4),
    /// BGP message with Add-Path (16-bit ASN)
    MESSAGE_ADDPATH(MESSAGE),
    /// BGP message with Add-Path (32-bit ASN)
    MESSAGE_AS4_ADDPATH(MESSAGE_AS4),
    /// Local BGP message with Add-Path (16-bit ASN)
    MESSAGE_LOCAL_ADDPATH(MESSAGE),
    /// Local BGP message with Add-Path (32-bit ASN)
    MESSAGE_AS4_LOCAL_ADDPATH(MESSAGE_AS4),
}

impl BGP4MP {
    /// Parse a BGP4MP record from the stream.
    ///
    /// # Arguments
    ///
    /// * `header` - The MRT record header
    /// * `stream` - The input stream positioned at the record body
    #[inline]
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        // Calculate actual body length for extended types
        let body_length = if header.record_type == 17 {
            // BGP4MP_ET
            header.length.saturating_sub(4)
        } else {
            header.length
        };

        match header.sub_type {
            subtypes::STATE_CHANGE => Ok(BGP4MP::STATE_CHANGE(STATE_CHANGE::parse(stream)?)),
            subtypes::MESSAGE => Ok(BGP4MP::MESSAGE(MESSAGE::parse(body_length, stream)?)),
            subtypes::ENTRY => Ok(BGP4MP::ENTRY(ENTRY::parse(body_length, stream)?)),
            subtypes::SNAPSHOT => Ok(BGP4MP::SNAPSHOT(SNAPSHOT::parse(body_length, stream)?)),
            subtypes::MESSAGE_AS4 => {
                Ok(BGP4MP::MESSAGE_AS4(MESSAGE_AS4::parse(body_length, stream)?))
            }
            subtypes::STATE_CHANGE_AS4 => {
                Ok(BGP4MP::STATE_CHANGE_AS4(STATE_CHANGE_AS4::parse(stream)?))
            }
            subtypes::MESSAGE_LOCAL => {
                Ok(BGP4MP::MESSAGE_LOCAL(MESSAGE::parse(body_length, stream)?))
            }
            subtypes::MESSAGE_AS4_LOCAL => Ok(BGP4MP::MESSAGE_AS4_LOCAL(MESSAGE_AS4::parse(
                body_length,
                stream,
            )?)),
            subtypes::MESSAGE_ADDPATH => {
                Ok(BGP4MP::MESSAGE_ADDPATH(MESSAGE::parse(body_length, stream)?))
            }
            subtypes::MESSAGE_AS4_ADDPATH => Ok(BGP4MP::MESSAGE_AS4_ADDPATH(MESSAGE_AS4::parse(
                body_length,
                stream,
            )?)),
            subtypes::MESSAGE_LOCAL_ADDPATH => Ok(BGP4MP::MESSAGE_LOCAL_ADDPATH(MESSAGE::parse(
                body_length,
                stream,
            )?)),
            subtypes::MESSAGE_AS4_LOCAL_ADDPATH => Ok(BGP4MP::MESSAGE_AS4_LOCAL_ADDPATH(
                MESSAGE_AS4::parse(body_length, stream)?,
            )),
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid BGP4MP subtype")),
        }
    }
}

/// BGP state change with 16-bit AS numbers.
#[derive(Debug, Clone)]
pub struct STATE_CHANGE {
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// Local AS number (16-bit)
    pub local_as: u16,
    /// Interface index
    pub interface: u16,
    /// Peer IP address (IPv4 or IPv6)
    pub peer_address: IpAddr,
    /// Local IP address (IPv4 or IPv6)
    pub local_address: IpAddr,
    /// Previous BGP FSM state
    pub old_state: u16,
    /// New BGP FSM state
    pub new_state: u16,
}

impl STATE_CHANGE {
    /// Parse a STATE_CHANGE record.
    ///
    /// Format:
    /// - 2 bytes: peer_as
    /// - 2 bytes: local_as
    /// - 2 bytes: interface
    /// - 2 bytes: AFI
    /// - variable: peer_address (4 or 16 bytes)
    /// - variable: local_address (4 or 16 bytes)
    /// - 2 bytes: old_state
    /// - 2 bytes: new_state
    #[inline]
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = read_afi(stream)?;
        let peer_address = read_ip_by_afi(stream, &afi)?;
        let local_address = read_ip_by_afi(stream, &afi)?;
        let old_state = stream.read_u16::<BigEndian>()?;
        let new_state = stream.read_u16::<BigEndian>()?;

        Ok(STATE_CHANGE {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            old_state,
            new_state,
        })
    }
}

/// BGP message with 16-bit AS numbers.
#[derive(Debug, Clone)]
pub struct MESSAGE {
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// Local AS number (16-bit)
    pub local_as: u16,
    /// Interface index
    pub interface: u16,
    /// Peer IP address (IPv4 or IPv6)
    pub peer_address: IpAddr,
    /// Local IP address (IPv4 or IPv6)
    pub local_address: IpAddr,
    /// Raw BGP message bytes
    pub message: Vec<u8>,
}

impl MESSAGE {
    /// Parse a MESSAGE record.
    ///
    /// Format:
    /// - 2 bytes: peer_as
    /// - 2 bytes: local_as
    /// - 2 bytes: interface
    /// - 2 bytes: AFI
    /// - variable: peer_address (4 or 16 bytes)
    /// - variable: local_address (4 or 16 bytes)
    /// - remaining: BGP message
    #[inline]
    pub fn parse(body_length: u32, stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = read_afi(stream)?;
        let peer_address = read_ip_by_afi(stream, &afi)?;
        let local_address = read_ip_by_afi(stream, &afi)?;

        // Calculate header size: 2 + 2 + 2 + 2 + (afi.size() * 2)
        let header_size = 8 + (afi.size() * 2);
        let message_len = body_length.saturating_sub(header_size) as usize;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message)?;

        Ok(MESSAGE {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            message,
        })
    }
}

/// BGP message with 32-bit AS numbers.
#[derive(Debug, Clone)]
pub struct MESSAGE_AS4 {
    /// Peer AS number (32-bit)
    pub peer_as: u32,
    /// Local AS number (32-bit)
    pub local_as: u32,
    /// Interface index
    pub interface: u16,
    /// Peer IP address (IPv4 or IPv6)
    pub peer_address: IpAddr,
    /// Local IP address (IPv4 or IPv6)
    pub local_address: IpAddr,
    /// Raw BGP message bytes
    pub message: Vec<u8>,
}

impl MESSAGE_AS4 {
    /// Parse a MESSAGE_AS4 record.
    ///
    /// Format:
    /// - 4 bytes: peer_as
    /// - 4 bytes: local_as
    /// - 2 bytes: interface
    /// - 2 bytes: AFI
    /// - variable: peer_address (4 or 16 bytes)
    /// - variable: local_address (4 or 16 bytes)
    /// - remaining: BGP message
    #[inline]
    pub fn parse(body_length: u32, stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u32::<BigEndian>()?;
        let local_as = stream.read_u32::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = read_afi(stream)?;
        let peer_address = read_ip_by_afi(stream, &afi)?;
        let local_address = read_ip_by_afi(stream, &afi)?;

        // Calculate header size: 4 + 4 + 2 + 2 + (afi.size() * 2)
        let header_size = 12 + (afi.size() * 2);
        let message_len = body_length.saturating_sub(header_size) as usize;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message)?;

        Ok(MESSAGE_AS4 {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            message,
        })
    }
}

/// BGP state change with 32-bit AS numbers.
#[derive(Debug, Clone)]
pub struct STATE_CHANGE_AS4 {
    /// Peer AS number (32-bit)
    pub peer_as: u32,
    /// Local AS number (32-bit)
    pub local_as: u32,
    /// Interface index
    pub interface: u16,
    /// Peer IP address (IPv4 or IPv6)
    pub peer_address: IpAddr,
    /// Local IP address (IPv4 or IPv6)
    pub local_address: IpAddr,
    /// Previous BGP FSM state
    pub old_state: u16,
    /// New BGP FSM state
    pub new_state: u16,
}

impl STATE_CHANGE_AS4 {
    /// Parse a STATE_CHANGE_AS4 record.
    ///
    /// Format:
    /// - 4 bytes: peer_as
    /// - 4 bytes: local_as
    /// - 2 bytes: interface
    /// - 2 bytes: AFI
    /// - variable: peer_address (4 or 16 bytes)
    /// - variable: local_address (4 or 16 bytes)
    /// - 2 bytes: old_state
    /// - 2 bytes: new_state
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u32::<BigEndian>()?;
        let local_as = stream.read_u32::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = read_afi(stream)?;
        let peer_address = read_ip_by_afi(stream, &afi)?;
        let local_address = read_ip_by_afi(stream, &afi)?;
        let old_state = stream.read_u16::<BigEndian>()?;
        let new_state = stream.read_u16::<BigEndian>()?;

        Ok(STATE_CHANGE_AS4 {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            old_state,
            new_state,
        })
    }
}

/// Deprecated snapshot pointer.
#[derive(Debug, Clone)]
pub struct SNAPSHOT {
    /// View number for multi-view recordings
    pub view_number: u16,
    /// Filename (NULL-terminated in wire format)
    pub filename: Vec<u8>,
}

impl SNAPSHOT {
    /// Parse a SNAPSHOT record.
    pub fn parse(body_length: u32, stream: &mut impl Read) -> std::io::Result<Self> {
        let view_number = stream.read_u16::<BigEndian>()?;

        let filename_len = body_length.saturating_sub(2) as usize;
        let mut filename = vec![0u8; filename_len];
        stream.read_exact(&mut filename)?;

        Ok(SNAPSHOT {
            view_number,
            filename,
        })
    }
}

/// Deprecated RIB entry format.
#[derive(Debug, Clone)]
pub struct ENTRY {
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// Local AS number (16-bit)
    pub local_as: u16,
    /// Interface index
    pub interface: u16,
    /// Peer IP address
    pub peer_address: IpAddr,
    /// Local IP address
    pub local_address: IpAddr,
    /// View number
    pub view_number: u16,
    /// Entry status
    pub status: u16,
    /// Time of last change (UNIX timestamp)
    pub time_last_change: u32,
    /// Next hop address
    pub next_hop: IpAddr,
    /// Address family identifier
    pub afi: u16,
    /// Subsequent AFI
    pub safi: u8,
    /// Prefix length in bits
    pub prefix_length: u8,
    /// Prefix bytes (variable length based on prefix_length)
    pub prefix: Vec<u8>,
    /// BGP path attributes
    pub attributes: Vec<u8>,
}

impl ENTRY {
    /// Parse an ENTRY record.
    pub fn parse(_body_length: u32, stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi_raw = stream.read_u16::<BigEndian>()?;
        let afi_enum = AFI::from_u16(afi_raw)?;
        let peer_address = read_ip_by_afi(stream, &afi_enum)?;
        let local_address = read_ip_by_afi(stream, &afi_enum)?;
        let view_number = stream.read_u16::<BigEndian>()?;
        let status = stream.read_u16::<BigEndian>()?;
        let time_last_change = stream.read_u32::<BigEndian>()?;

        // Next hop AFI for ENTRY records
        let next_hop_afi = read_afi(stream)?;
        let next_hop = read_ip_by_afi(stream, &next_hop_afi)?;

        let afi = stream.read_u16::<BigEndian>()?;
        let safi = stream.read_u8()?;
        let prefix_length = stream.read_u8()?;
        let prefix = read_prefix(stream, prefix_length)?;

        // Read attribute length and attributes
        let attr_len = stream.read_u16::<BigEndian>()? as usize;
        let mut attributes = vec![0u8; attr_len];
        stream.read_exact(&mut attributes)?;

        Ok(ENTRY {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            view_number,
            status,
            time_last_change,
            next_hop,
            afi,
            safi,
            prefix_length,
            prefix,
            attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_bgp4mp_state_change() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 16,
            sub_type: 0, // STATE_CHANGE
            length: 20,  // 2+2+2+2+4+4+2+2 = 20
        };
        let data: &[u8] = &[
            0x00, 0x64, // peer_as = 100
            0x00, 0xC8, // local_as = 200
            0x00, 0x00, // interface = 0
            0x00, 0x01, // AFI = IPv4
            192, 168, 1, 1, // peer_address
            10, 0, 0, 1, // local_address
            0x00, 0x01, // old_state = 1
            0x00, 0x06, // new_state = 6
        ];
        let result = BGP4MP::parse(&header, &mut data.as_ref()).unwrap();
        match result {
            BGP4MP::STATE_CHANGE(sc) => {
                assert_eq!(sc.peer_as, 100);
                assert_eq!(sc.local_as, 200);
                assert_eq!(sc.peer_address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(sc.local_address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(sc.old_state, 1);
                assert_eq!(sc.new_state, 6);
            }
            _ => panic!("Expected STATE_CHANGE"),
        }
    }

    #[test]
    fn test_parse_bgp4mp_message_as4() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 16,
            sub_type: 4, // MESSAGE_AS4
            length: 24,  // 4+4+2+2+4+4+4 = 24
        };
        let data: &[u8] = &[
            0x00, 0x00, 0xFD, 0xE8, // peer_as = 65000
            0x00, 0x00, 0xFD, 0xE9, // local_as = 65001
            0x00, 0x00, // interface = 0
            0x00, 0x01, // AFI = IPv4
            192, 168, 1, 1, // peer_address
            10, 0, 0, 1, // local_address
            0x01, 0x02, 0x03, 0x04, // message
        ];
        let result = BGP4MP::parse(&header, &mut data.as_ref()).unwrap();
        match result {
            BGP4MP::MESSAGE_AS4(msg) => {
                assert_eq!(msg.peer_as, 65000);
                assert_eq!(msg.local_as, 65001);
                assert_eq!(msg.peer_address, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(msg.message, vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected MESSAGE_AS4"),
        }
    }

    #[test]
    fn test_parse_bgp4mp_message_ipv6() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 16,
            sub_type: 1, // MESSAGE
            length: 44,  // 2+2+2+2+16+16+4 = 44
        };
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x64]); // peer_as = 100
        data.extend_from_slice(&[0x00, 0xC8]); // local_as = 200
        data.extend_from_slice(&[0x00, 0x00]); // interface = 0
        data.extend_from_slice(&[0x00, 0x02]); // AFI = IPv6
        // peer: 2001:db8::1
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // local: 2001:db8::2
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // message

        let result = BGP4MP::parse(&header, &mut data.as_slice()).unwrap();
        match result {
            BGP4MP::MESSAGE(msg) => {
                assert_eq!(msg.peer_as, 100);
                assert_eq!(msg.local_as, 200);
                assert!(msg.peer_address.is_ipv6());
                assert!(msg.local_address.is_ipv6());
                assert_eq!(msg.message, vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected MESSAGE"),
        }
    }
}
