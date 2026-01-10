//! Legacy BGP4+ MRT record parsing (Types 9, 10).
//!
//! This module handles the deprecated BGP4+ record types which support
//! IPv6 peers with 16-bit AS numbers. For modern BGP data, use `bgp4mp`.

#![allow(non_camel_case_types)]

use crate::address::read_ipv6;
use crate::Header;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::Ipv6Addr;

/// BGP4PLUS subtype constants
mod subtypes {
    pub const NULL: u16 = 0;
    pub const UPDATE: u16 = 1;
    pub const PREF_UPDATE: u16 = 2;
    pub const STATE_CHANGE: u16 = 3;
    pub const SYNC: u16 = 4;
    pub const OPEN: u16 = 5;
    pub const NOTIFY: u16 = 6;
    pub const KEEPALIVE: u16 = 7;
}

/// Legacy BGP4+ record enum for IPv6 peers.
///
/// Similar to `BGP` but uses IPv6 addresses. This is a deprecated record type;
/// prefer `BGP4MP` for new implementations.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum BGP4PLUS {
    /// Null subtype
    NULL,
    /// BGP UPDATE message
    UPDATE(MESSAGE),
    /// Preference update (reserved)
    PREF_UPDATE,
    /// BGP state change notification
    STATE_CHANGE(STATE_CHANGE),
    /// RIB sync record
    SYNC(SYNC),
    /// BGP OPEN message
    OPEN(MESSAGE),
    /// BGP NOTIFICATION message
    NOTIFY(MESSAGE),
    /// BGP KEEPALIVE message
    KEEPALIVE(MESSAGE),
}

impl BGP4PLUS {
    /// Parse a BGP4PLUS record from the stream.
    ///
    /// # Arguments
    ///
    /// * `header` - The MRT record header
    /// * `stream` - The input stream positioned at the record body
    #[inline]
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        match header.sub_type {
            subtypes::NULL => Ok(BGP4PLUS::NULL),
            subtypes::UPDATE => Ok(BGP4PLUS::UPDATE(MESSAGE::parse(header, stream)?)),
            subtypes::PREF_UPDATE => Ok(BGP4PLUS::PREF_UPDATE),
            subtypes::STATE_CHANGE => Ok(BGP4PLUS::STATE_CHANGE(STATE_CHANGE::parse(stream)?)),
            subtypes::SYNC => Ok(BGP4PLUS::SYNC(SYNC::parse(header, stream)?)),
            subtypes::OPEN => Ok(BGP4PLUS::OPEN(MESSAGE::parse(header, stream)?)),
            subtypes::NOTIFY => Ok(BGP4PLUS::NOTIFY(MESSAGE::parse(header, stream)?)),
            subtypes::KEEPALIVE => Ok(BGP4PLUS::KEEPALIVE(MESSAGE::parse(header, stream)?)),
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid BGP4PLUS subtype")),
        }
    }
}

/// BGP message record for IPv6 peers.
///
/// Used for UPDATE, OPEN, NOTIFY, and KEEPALIVE message types.
#[derive(Debug, Clone)]
pub struct MESSAGE {
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// Peer IPv6 address
    pub peer_ip: Ipv6Addr,
    /// Local AS number (16-bit)
    pub local_as: u16,
    /// Local IPv6 address
    pub local_ip: Ipv6Addr,
    /// Raw BGP message bytes (including BGP header)
    pub message: Vec<u8>,
}

impl MESSAGE {
    /// Parse a BGP4PLUS MESSAGE from the stream.
    ///
    /// Format:
    /// - 2 bytes: peer_as
    /// - 16 bytes: peer_ip (IPv6)
    /// - 2 bytes: local_as
    /// - 16 bytes: local_ip (IPv6)
    /// - remaining: message
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = read_ipv6(stream)?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let local_ip = read_ipv6(stream)?;

        // Calculate message length: total minus header fields (2 + 16 + 2 + 16 = 36 bytes)
        let message_len = header.length.saturating_sub(36) as usize;
        let mut message = vec![0u8; message_len];
        stream.read_exact(&mut message)?;

        Ok(MESSAGE {
            peer_as,
            peer_ip,
            local_as,
            local_ip,
            message,
        })
    }
}

/// BGP state change notification for IPv6 peers.
///
/// Records when a BGP session changes state (e.g., from Established to Idle).
#[derive(Debug, Clone)]
pub struct STATE_CHANGE {
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// Peer IPv6 address
    pub peer_ip: Ipv6Addr,
    /// Previous BGP FSM state
    pub old_state: u16,
    /// New BGP FSM state
    pub new_state: u16,
}

impl STATE_CHANGE {
    /// Parse a STATE_CHANGE record from the stream.
    ///
    /// Format:
    /// - 2 bytes: peer_as
    /// - 16 bytes: peer_ip
    /// - 2 bytes: old_state
    /// - 2 bytes: new_state
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = read_ipv6(stream)?;
        let old_state = stream.read_u16::<BigEndian>()?;
        let new_state = stream.read_u16::<BigEndian>()?;

        Ok(STATE_CHANGE {
            peer_as,
            peer_ip,
            old_state,
            new_state,
        })
    }
}

/// BGP RIB synchronization record.
///
/// Deprecated record type used to indicate RIB recording boundaries.
#[derive(Debug, Clone)]
pub struct SYNC {
    /// View number for multi-view RIB recordings
    pub view_number: u16,
    /// Filename (NULL-terminated in wire format)
    pub filename: Vec<u8>,
}

impl SYNC {
    /// Parse a SYNC record from the stream.
    ///
    /// Format:
    /// - 2 bytes: view_number
    /// - remaining: filename (NULL-terminated)
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        let view_number = stream.read_u16::<BigEndian>()?;

        // Read remaining bytes as filename
        let filename_len = header.length.saturating_sub(2) as usize;
        let mut filename = vec![0u8; filename_len];
        stream.read_exact(&mut filename)?;

        Ok(SYNC {
            view_number,
            filename,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bgp4plus_state_change() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 9,
            sub_type: 3, // STATE_CHANGE
            length: 22,  // 2 + 16 + 2 + 2
        };
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x64]); // peer_as = 100
        // peer_ip: 2001:db8::1
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x00, 0x01]); // old_state = 1
        data.extend_from_slice(&[0x00, 0x06]); // new_state = 6

        let result = BGP4PLUS::parse(&header, &mut data.as_slice()).unwrap();
        match result {
            BGP4PLUS::STATE_CHANGE(sc) => {
                assert_eq!(sc.peer_as, 100);
                assert_eq!(sc.peer_ip, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(sc.old_state, 1);
                assert_eq!(sc.new_state, 6);
            }
            _ => panic!("Expected STATE_CHANGE"),
        }
    }

    #[test]
    fn test_parse_bgp4plus_message() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 9,
            sub_type: 1, // UPDATE
            length: 40,  // 36 bytes header + 4 bytes message
        };
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x64]); // peer_as = 100
        // peer_ip: 2001:db8::1
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x00, 0xC8]); // local_as = 200
        // local_ip: 2001:db8::2
        data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // message

        let result = BGP4PLUS::parse(&header, &mut data.as_slice()).unwrap();
        match result {
            BGP4PLUS::UPDATE(msg) => {
                assert_eq!(msg.peer_as, 100);
                assert_eq!(msg.peer_ip, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(msg.local_as, 200);
                assert_eq!(msg.local_ip, "2001:db8::2".parse::<Ipv6Addr>().unwrap());
                assert_eq!(msg.message, vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected UPDATE"),
        }
    }
}
