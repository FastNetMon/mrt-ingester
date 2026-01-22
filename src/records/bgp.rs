// SPDX-License-Identifier: MIT OR Apache-2.0

//! Legacy BGP MRT record parsing (Type 5).
//!
//! This module handles the deprecated BGP record type which only supports
//! IPv4 peers and 16-bit AS numbers. For modern BGP data, use `bgp4mp`.

#![allow(non_camel_case_types)]

use crate::address::read_ipv4;
use crate::Header;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::Ipv4Addr;

/// BGP subtype constants
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

/// Legacy BGP record enum.
///
/// Represents different BGP message types captured in MRT format.
/// This is a deprecated record type; prefer `BGP4MP` for new implementations.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum BGP {
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

impl BGP {
    /// Parse a BGP record from the stream.
    ///
    /// # Arguments
    ///
    /// * `header` - The MRT record header
    /// * `stream` - The input stream positioned at the record body
    #[inline]
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        match header.sub_type {
            subtypes::NULL => Ok(BGP::NULL),
            subtypes::UPDATE => Ok(BGP::UPDATE(MESSAGE::parse(header, stream)?)),
            subtypes::PREF_UPDATE => Ok(BGP::PREF_UPDATE),
            subtypes::STATE_CHANGE => Ok(BGP::STATE_CHANGE(STATE_CHANGE::parse(stream)?)),
            subtypes::SYNC => Ok(BGP::SYNC(SYNC::parse(header, stream)?)),
            subtypes::OPEN => Ok(BGP::OPEN(MESSAGE::parse(header, stream)?)),
            subtypes::NOTIFY => Ok(BGP::NOTIFY(MESSAGE::parse(header, stream)?)),
            subtypes::KEEPALIVE => Ok(BGP::KEEPALIVE(MESSAGE::parse(header, stream)?)),
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid BGP subtype")),
        }
    }
}

/// BGP message record for IPv4 peers.
///
/// Used for UPDATE, OPEN, NOTIFY, and KEEPALIVE message types.
#[derive(Debug, Clone)]
pub struct MESSAGE {
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// Peer IPv4 address
    pub peer_ip: Ipv4Addr,
    /// Local AS number (16-bit)
    pub local_as: u16,
    /// Local IPv4 address
    pub local_ip: Ipv4Addr,
    /// Raw BGP message bytes (including BGP header)
    pub message: Vec<u8>,
}

impl MESSAGE {
    /// Parse a BGP MESSAGE from the stream.
    ///
    /// Format:
    /// - 2 bytes: peer_as
    /// - 4 bytes: peer_ip
    /// - 2 bytes: local_as
    /// - 4 bytes: local_ip
    /// - remaining: message
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = read_ipv4(stream)?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let local_ip = read_ipv4(stream)?;

        // Calculate message length: total minus header fields (2 + 4 + 2 + 4 = 12 bytes)
        let message_len = header.length.saturating_sub(12) as usize;
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

/// BGP state change notification.
///
/// Records when a BGP session changes state (e.g., from Established to Idle).
#[derive(Debug, Clone)]
pub struct STATE_CHANGE {
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// Peer IPv4 address
    pub peer_ip: Ipv4Addr,
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
    /// - 4 bytes: peer_ip
    /// - 2 bytes: old_state
    /// - 2 bytes: new_state
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = read_ipv4(stream)?;
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
    fn test_parse_bgp_state_change() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 5,
            sub_type: 3, // STATE_CHANGE
            length: 10,
        };
        let data: &[u8] = &[
            0x00, 0x64, // peer_as = 100
            192, 168, 1, 1, // peer_ip
            0x00, 0x01, // old_state = 1
            0x00, 0x06, // new_state = 6 (Established)
        ];
        let result = BGP::parse(&header, &mut data.as_ref()).unwrap();
        match result {
            BGP::STATE_CHANGE(sc) => {
                assert_eq!(sc.peer_as, 100);
                assert_eq!(sc.peer_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(sc.old_state, 1);
                assert_eq!(sc.new_state, 6);
            }
            _ => panic!("Expected STATE_CHANGE"),
        }
    }

    #[test]
    fn test_parse_bgp_message() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 5,
            sub_type: 1, // UPDATE
            length: 16,  // 12 bytes header + 4 bytes message
        };
        let data: &[u8] = &[
            0x00, 0x64, // peer_as = 100
            192, 168, 1, 1, // peer_ip
            0x00, 0xC8, // local_as = 200
            10, 0, 0, 1, // local_ip
            0x01, 0x02, 0x03, 0x04, // message
        ];
        let result = BGP::parse(&header, &mut data.as_ref()).unwrap();
        match result {
            BGP::UPDATE(msg) => {
                assert_eq!(msg.peer_as, 100);
                assert_eq!(msg.peer_ip, Ipv4Addr::new(192, 168, 1, 1));
                assert_eq!(msg.local_as, 200);
                assert_eq!(msg.local_ip, Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(msg.message, vec![0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected UPDATE"),
        }
    }

    #[test]
    fn test_parse_bgp_sync() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 5,
            sub_type: 4, // SYNC
            length: 12,
        };
        let data: &[u8] = &[
            0x00, 0x01, // view_number = 1
            b't', b'e', b's', b't', b'.', b'm', b'r', b't', 0x00, 0x00, // filename
        ];
        let result = BGP::parse(&header, &mut data.as_ref()).unwrap();
        match result {
            BGP::SYNC(sync) => {
                assert_eq!(sync.view_number, 1);
                assert_eq!(sync.filename.len(), 10);
            }
            _ => panic!("Expected SYNC"),
        }
    }
}
