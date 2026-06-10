// SPDX-License-Identifier: MIT OR Apache-2.0

//! TABLE_DUMP and TABLE_DUMP_V2 MRT record parsing (Types 12, 13).
//!
//! These record types contain RIB (Routing Information Base) dumps,
//! used by route collectors to capture BGP routing table snapshots.

#![allow(non_camel_case_types)]

use crate::address::{prefix_bytes_needed, read_afi, read_ip_by_afi, read_ipv4, read_ipv6};
use crate::Header;
use crate::AFI;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::IpAddr;

/// TABLE_DUMP_V2 subtype constants
mod subtypes {
    pub const PEER_INDEX_TABLE: u16 = 1;
    pub const RIB_IPV4_UNICAST: u16 = 2;
    pub const RIB_IPV4_MULTICAST: u16 = 3;
    pub const RIB_IPV6_UNICAST: u16 = 4;
    pub const RIB_IPV6_MULTICAST: u16 = 5;
    pub const RIB_GENERIC: u16 = 6;
    // RFC 8050 Add-Path extensions
    pub const RIB_IPV4_UNICAST_ADDPATH: u16 = 8;
    pub const RIB_IPV4_MULTICAST_ADDPATH: u16 = 9;
    pub const RIB_IPV6_UNICAST_ADDPATH: u16 = 10;
    pub const RIB_IPV6_MULTICAST_ADDPATH: u16 = 11;
    pub const RIB_GENERIC_ADDPATH: u16 = 12;
}

/// TABLE_DUMP record (type 12).
///
/// The original RIB dump format, one entry per record.
#[derive(Debug, Clone)]
pub struct TABLE_DUMP {
    /// View number for multi-view recordings
    pub view_number: u16,
    /// Sequence number within the dump
    pub sequence_number: u16,
    /// IP prefix (IPv4 or IPv6 based on header subtype)
    pub prefix: IpAddr,
    /// Prefix length in bits
    pub prefix_length: u8,
    /// Entry status
    pub status: u8,
    /// Time this route was originated
    pub originated_time: u32,
    /// Peer IP address
    pub peer_address: IpAddr,
    /// Peer AS number (16-bit)
    pub peer_as: u16,
    /// BGP path attributes
    pub attributes: Vec<u8>,
}

impl TABLE_DUMP {
    /// Parse a TABLE_DUMP record.
    ///
    /// The AFI is determined by the header subtype:
    /// - subtype 1 = AFI_IPv4
    /// - subtype 2 = AFI_IPv6
    #[inline]
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        let afi = match header.sub_type {
            1 => AFI::IPV4,
            2 => AFI::IPV6,
            _ => return Err(Error::new(ErrorKind::InvalidData, "invalid TABLE_DUMP subtype")),
        };

        let view_number = stream.read_u16::<BigEndian>()?;
        let sequence_number = stream.read_u16::<BigEndian>()?;

        let prefix = read_ip_by_afi(stream, &afi)?;
        let prefix_length = stream.read_u8()?;
        let status = stream.read_u8()?;
        let originated_time = stream.read_u32::<BigEndian>()?;
        let peer_address = read_ip_by_afi(stream, &afi)?;
        let peer_as = stream.read_u16::<BigEndian>()?;

        let attr_len = stream.read_u16::<BigEndian>()? as usize;
        let mut attributes = vec![0u8; attr_len];
        stream.read_exact(&mut attributes)?;

        Ok(TABLE_DUMP {
            view_number,
            sequence_number,
            prefix,
            prefix_length,
            status,
            originated_time,
            peer_address,
            peer_as,
            attributes,
        })
    }
}

/// TABLE_DUMP_V2 record (type 13).
///
/// The modern RIB dump format with improved efficiency and support for
/// multiple RIB entries per record.
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub enum TABLE_DUMP_V2 {
    /// Peer index table (must appear first in dump)
    PEER_INDEX_TABLE(PEER_INDEX_TABLE),
    /// IPv4 unicast RIB entries
    RIB_IPV4_UNICAST(RIB_AFI),
    /// IPv4 multicast RIB entries
    RIB_IPV4_MULTICAST(RIB_AFI),
    /// IPv6 unicast RIB entries
    RIB_IPV6_UNICAST(RIB_AFI),
    /// IPv6 multicast RIB entries
    RIB_IPV6_MULTICAST(RIB_AFI),
    /// Generic RIB entries (includes AFI/SAFI)
    RIB_GENERIC(RIB_GENERIC),
    /// IPv4 unicast RIB entries with Add-Path
    RIB_IPV4_UNICAST_ADDPATH(RIB_AFI_ADDPATH),
    /// IPv4 multicast RIB entries with Add-Path
    RIB_IPV4_MULTICAST_ADDPATH(RIB_AFI_ADDPATH),
    /// IPv6 unicast RIB entries with Add-Path
    RIB_IPV6_UNICAST_ADDPATH(RIB_AFI_ADDPATH),
    /// IPv6 multicast RIB entries with Add-Path
    RIB_IPV6_MULTICAST_ADDPATH(RIB_AFI_ADDPATH),
    /// Generic RIB entries with Add-Path
    RIB_GENERIC_ADDPATH(RIB_GENERIC_ADDPATH),
}

impl TABLE_DUMP_V2 {
    /// Parse a TABLE_DUMP_V2 record.
    #[inline]
    pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Self> {
        match header.sub_type {
            subtypes::PEER_INDEX_TABLE => Ok(TABLE_DUMP_V2::PEER_INDEX_TABLE(
                PEER_INDEX_TABLE::parse(stream)?,
            )),
            subtypes::RIB_IPV4_UNICAST => Ok(TABLE_DUMP_V2::RIB_IPV4_UNICAST(RIB_AFI::parse(
                &AFI::IPV4,
                stream,
            )?)),
            subtypes::RIB_IPV4_MULTICAST => Ok(TABLE_DUMP_V2::RIB_IPV4_MULTICAST(RIB_AFI::parse(
                &AFI::IPV4,
                stream,
            )?)),
            subtypes::RIB_IPV6_UNICAST => Ok(TABLE_DUMP_V2::RIB_IPV6_UNICAST(RIB_AFI::parse(
                &AFI::IPV6,
                stream,
            )?)),
            subtypes::RIB_IPV6_MULTICAST => Ok(TABLE_DUMP_V2::RIB_IPV6_MULTICAST(RIB_AFI::parse(
                &AFI::IPV6,
                stream,
            )?)),
            subtypes::RIB_GENERIC => {
                Ok(TABLE_DUMP_V2::RIB_GENERIC(RIB_GENERIC::parse(stream)?))
            }
            subtypes::RIB_IPV4_UNICAST_ADDPATH => Ok(TABLE_DUMP_V2::RIB_IPV4_UNICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(&AFI::IPV4, stream)?,
            )),
            subtypes::RIB_IPV4_MULTICAST_ADDPATH => Ok(TABLE_DUMP_V2::RIB_IPV4_MULTICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(&AFI::IPV4, stream)?,
            )),
            subtypes::RIB_IPV6_UNICAST_ADDPATH => Ok(TABLE_DUMP_V2::RIB_IPV6_UNICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(&AFI::IPV6, stream)?,
            )),
            subtypes::RIB_IPV6_MULTICAST_ADDPATH => Ok(TABLE_DUMP_V2::RIB_IPV6_MULTICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(&AFI::IPV6, stream)?,
            )),
            subtypes::RIB_GENERIC_ADDPATH => Ok(TABLE_DUMP_V2::RIB_GENERIC_ADDPATH(
                RIB_GENERIC_ADDPATH::parse(stream)?,
            )),
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid TABLE_DUMP_V2 subtype")),
        }
    }
}

/// Peer index table for TABLE_DUMP_V2.
///
/// This record must appear at the start of a TABLE_DUMP_V2 file and
/// defines the peer index mappings used in subsequent RIB entries.
#[derive(Debug, Clone)]
pub struct PEER_INDEX_TABLE {
    /// BGP identifier of the collector
    pub collector_id: u32,
    /// View name (may be empty)
    pub view_name: String,
    /// List of peers in this dump
    pub peer_entries: Vec<PeerEntry>,
}

impl PEER_INDEX_TABLE {
    /// Parse a PEER_INDEX_TABLE record.
    #[inline]
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let collector_id = stream.read_u32::<BigEndian>()?;
        let view_name_length = stream.read_u16::<BigEndian>()? as usize;

        let mut view_name_bytes = vec![0u8; view_name_length];
        stream.read_exact(&mut view_name_bytes)?;
        let view_name = String::from_utf8_lossy(&view_name_bytes).into_owned();

        let peer_count = stream.read_u16::<BigEndian>()? as usize;
        let mut peer_entries = Vec::with_capacity(peer_count);

        for _ in 0..peer_count {
            peer_entries.push(PeerEntry::parse(stream)?);
        }

        Ok(PEER_INDEX_TABLE {
            collector_id,
            view_name,
            peer_entries,
        })
    }
}

/// Peer entry within a PEER_INDEX_TABLE.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Peer type flags:
    /// - Bit 0: AS number size (0 = 16-bit, 1 = 32-bit)
    /// - Bit 1: IP address type (0 = IPv4, 1 = IPv6)
    pub peer_type: u8,
    /// Peer BGP identifier
    pub peer_bgp_id: u32,
    /// Peer IP address
    pub peer_ip_address: IpAddr,
    /// Peer AS number (stored as u32, may have been 16-bit on wire)
    pub peer_as: u32,
}

impl PeerEntry {
    /// Parse a PeerEntry from the stream.
    #[inline]
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_type = stream.read_u8()?;
        let peer_bgp_id = stream.read_u32::<BigEndian>()?;

        // RFC 6396: Bit 0 = Address Family (0 = IPv4, 1 = IPv6)
        let is_ipv6 = (peer_type & 0x01) != 0;
        let peer_ip_address = if is_ipv6 {
            IpAddr::V6(read_ipv6(stream)?)
        } else {
            IpAddr::V4(read_ipv4(stream)?)
        };

        // RFC 6396: Bit 1 = AS Size (0 = 16-bit, 1 = 32-bit)
        let is_as4 = (peer_type & 0x02) != 0;
        let peer_as = if is_as4 {
            stream.read_u32::<BigEndian>()?
        } else {
            stream.read_u16::<BigEndian>()? as u32
        };

        Ok(PeerEntry {
            peer_type,
            peer_bgp_id,
            peer_ip_address,
            peer_as,
        })
    }
}

/// RIB entry in TABLE_DUMP_V2.
#[derive(Debug, Clone)]
pub struct RIBEntry {
    /// Index into the peer index table
    pub peer_index: u16,
    /// Time this route was originated
    pub originated_time: u32,
    /// BGP path attributes
    pub attributes: Vec<u8>,
}

impl RIBEntry {
    /// Parse a RIBEntry from the stream.
    #[inline]
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_index = stream.read_u16::<BigEndian>()?;
        let originated_time = stream.read_u32::<BigEndian>()?;
        let attr_len = stream.read_u16::<BigEndian>()? as usize;

        let mut attributes = vec![0u8; attr_len];
        stream.read_exact(&mut attributes)?;

        Ok(RIBEntry {
            peer_index,
            originated_time,
            attributes,
        })
    }
}

/// AFI-specific RIB record (IPv4 or IPv6 unicast/multicast).
#[derive(Debug, Clone)]
pub struct RIB_AFI {
    /// Sequence number within the dump
    pub sequence_number: u32,
    /// Prefix length in bits
    pub prefix_length: u8,
    /// Prefix bytes (variable length based on prefix_length)
    pub prefix: Vec<u8>,
    /// RIB entries for this prefix
    pub entries: Vec<RIBEntry>,
}

impl RIB_AFI {
    /// Parse a RIB_AFI record.
    #[inline]
    pub fn parse(_afi: &AFI, stream: &mut impl Read) -> std::io::Result<Self> {
        let sequence_number = stream.read_u32::<BigEndian>()?;
        let prefix_length = stream.read_u8()?;

        let prefix_bytes = prefix_bytes_needed(prefix_length);
        let mut prefix = vec![0u8; prefix_bytes];
        stream.read_exact(&mut prefix)?;

        let entry_count = stream.read_u16::<BigEndian>()? as usize;
        let mut entries = Vec::with_capacity(entry_count);

        for _ in 0..entry_count {
            entries.push(RIBEntry::parse(stream)?);
        }

        Ok(RIB_AFI {
            sequence_number,
            prefix_length,
            prefix,
            entries,
        })
    }
}

/// Zero-copy view of a TABLE_DUMP_V2 RIB record (subtypes 2-5 and ADD-PATH 8-11).
///
/// Unlike [`RIB_AFI`], this borrows directly from the record body buffer:
/// no per-entry heap allocations and no copying of attribute bytes. Entries
/// are decoded lazily via [`RibRef::entries`].
#[derive(Debug, Clone, Copy)]
pub struct RibRef<'a> {
    /// Address family of the prefix
    pub afi: AFI,
    /// True for the *_MULTICAST subtypes
    pub multicast: bool,
    /// True for the RFC 8050 ADD-PATH subtypes (entries carry a path identifier)
    pub addpath: bool,
    /// Sequence number within the dump
    pub sequence_number: u32,
    /// Prefix length in bits
    pub prefix_length: u8,
    /// Prefix bytes (variable length based on prefix_length)
    pub prefix: &'a [u8],
    /// Number of RIB entries following the prefix
    pub entry_count: u16,
    entries_data: &'a [u8],
}

impl<'a> RibRef<'a> {
    /// Parse the fixed part of a RIB record from a record body slice.
    ///
    /// The entries themselves are not validated here; they are decoded
    /// on demand by the iterator returned from [`RibRef::entries`].
    #[inline]
    pub fn parse(afi: AFI, multicast: bool, addpath: bool, body: &'a [u8]) -> std::io::Result<Self> {
        fn eof() -> Error {
            Error::new(ErrorKind::UnexpectedEof, "truncated RIB record")
        }

        let (seq, rest) = body.split_at_checked(4).ok_or_else(eof)?;
        let sequence_number = u32::from_be_bytes(seq.try_into().unwrap());

        let (&prefix_length, rest) = rest.split_first().ok_or_else(eof)?;
        let (prefix, rest) = rest
            .split_at_checked(prefix_bytes_needed(prefix_length))
            .ok_or_else(eof)?;

        let (cnt, rest) = rest.split_at_checked(2).ok_or_else(eof)?;
        let entry_count = u16::from_be_bytes(cnt.try_into().unwrap());

        Ok(RibRef {
            afi,
            multicast,
            addpath,
            sequence_number,
            prefix_length,
            prefix,
            entry_count,
            entries_data: rest,
        })
    }

    /// Iterate over the RIB entries without allocating.
    #[inline]
    pub fn entries(&self) -> RibEntryIter<'a> {
        RibEntryIter {
            data: self.entries_data,
            remaining: self.entry_count,
            addpath: self.addpath,
        }
    }
}

/// Zero-copy view of a single RIB entry; attributes borrow the body buffer.
#[derive(Debug, Clone, Copy)]
pub struct RibEntryRef<'a> {
    /// Index into the peer index table
    pub peer_index: u16,
    /// Time this route was originated
    pub originated_time: u32,
    /// Path identifier (ADD-PATH subtypes only)
    pub path_id: Option<u32>,
    /// BGP path attributes
    pub attributes: &'a [u8],
}

/// Lazy iterator over the entries of a [`RibRef`].
#[derive(Debug, Clone)]
pub struct RibEntryIter<'a> {
    data: &'a [u8],
    remaining: u16,
    addpath: bool,
}

impl<'a> Iterator for RibEntryIter<'a> {
    type Item = std::io::Result<RibEntryRef<'a>>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        let fixed_len = if self.addpath { 12 } else { 8 };
        let Some((head, rest)) = self.data.split_at_checked(fixed_len) else {
            self.remaining = 0;
            return Some(Err(Error::new(
                ErrorKind::UnexpectedEof,
                "truncated RIB entry",
            )));
        };

        let peer_index = u16::from_be_bytes([head[0], head[1]]);
        let originated_time = u32::from_be_bytes([head[2], head[3], head[4], head[5]]);
        let (path_id, attr_len) = if self.addpath {
            let path_id = u32::from_be_bytes([head[6], head[7], head[8], head[9]]);
            (Some(path_id), u16::from_be_bytes([head[10], head[11]]))
        } else {
            (None, u16::from_be_bytes([head[6], head[7]]))
        };

        let Some((attributes, rest)) = rest.split_at_checked(attr_len as usize) else {
            self.remaining = 0;
            return Some(Err(Error::new(
                ErrorKind::UnexpectedEof,
                "truncated RIB entry attributes",
            )));
        };
        self.data = rest;

        Some(Ok(RibEntryRef {
            peer_index,
            originated_time,
            path_id,
            attributes,
        }))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining as usize))
    }
}

/// Generic RIB record with explicit AFI/SAFI.
#[derive(Debug, Clone)]
pub struct RIB_GENERIC {
    /// Sequence number within the dump
    pub sequence_number: u32,
    /// Address family identifier
    pub afi: AFI,
    /// Subsequent AFI
    pub safi: u8,
    /// NLRI (Network Layer Reachability Information)
    pub nlri: Vec<u8>,
    /// RIB entries for this NLRI
    pub entries: Vec<RIBEntry>,
}

impl RIB_GENERIC {
    /// Parse a RIB_GENERIC record.
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let sequence_number = stream.read_u32::<BigEndian>()?;
        let afi = read_afi(stream)?;
        let safi = stream.read_u8()?;

        // NLRI is preceded by length
        let nlri_len = stream.read_u16::<BigEndian>()? as usize;
        let mut nlri = vec![0u8; nlri_len];
        stream.read_exact(&mut nlri)?;

        let entry_count = stream.read_u16::<BigEndian>()? as usize;
        let mut entries = Vec::with_capacity(entry_count);

        for _ in 0..entry_count {
            entries.push(RIBEntry::parse(stream)?);
        }

        Ok(RIB_GENERIC {
            sequence_number,
            afi,
            safi,
            nlri,
            entries,
        })
    }
}

/// RIB entry with Add-Path extension.
#[derive(Debug, Clone)]
pub struct RIBEntryAddPath {
    /// Index into the peer index table
    pub peer_index: u16,
    /// Time this route was originated
    pub originated_time: u32,
    /// Path identifier for Add-Path
    pub path_identifier: u32,
    /// BGP path attributes
    pub attributes: Vec<u8>,
}

impl RIBEntryAddPath {
    /// Parse a RIBEntryAddPath from the stream.
    #[inline]
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let peer_index = stream.read_u16::<BigEndian>()?;
        let originated_time = stream.read_u32::<BigEndian>()?;
        let path_identifier = stream.read_u32::<BigEndian>()?;
        let attr_len = stream.read_u16::<BigEndian>()? as usize;

        let mut attributes = vec![0u8; attr_len];
        stream.read_exact(&mut attributes)?;

        Ok(RIBEntryAddPath {
            peer_index,
            originated_time,
            path_identifier,
            attributes,
        })
    }
}

/// AFI-specific RIB record with Add-Path extension.
#[derive(Debug, Clone)]
pub struct RIB_AFI_ADDPATH {
    /// Sequence number within the dump
    pub sequence_number: u32,
    /// Prefix length in bits
    pub prefix_length: u8,
    /// Prefix bytes (variable length based on prefix_length)
    pub prefix: Vec<u8>,
    /// RIB entries with path identifiers
    pub entries: Vec<RIBEntryAddPath>,
}

impl RIB_AFI_ADDPATH {
    /// Parse a RIB_AFI_ADDPATH record.
    #[inline]
    pub fn parse(_afi: &AFI, stream: &mut impl Read) -> std::io::Result<Self> {
        let sequence_number = stream.read_u32::<BigEndian>()?;
        let prefix_length = stream.read_u8()?;

        let prefix_bytes = prefix_bytes_needed(prefix_length);
        let mut prefix = vec![0u8; prefix_bytes];
        stream.read_exact(&mut prefix)?;

        let entry_count = stream.read_u16::<BigEndian>()? as usize;
        let mut entries = Vec::with_capacity(entry_count);

        for _ in 0..entry_count {
            entries.push(RIBEntryAddPath::parse(stream)?);
        }

        Ok(RIB_AFI_ADDPATH {
            sequence_number,
            prefix_length,
            prefix,
            entries,
        })
    }
}

/// Generic RIB record with Add-Path extension.
#[derive(Debug, Clone)]
pub struct RIB_GENERIC_ADDPATH {
    /// Sequence number within the dump
    pub sequence_number: u32,
    /// Address family identifier
    pub afi: AFI,
    /// Subsequent AFI
    pub safi: u8,
    /// NLRI (Network Layer Reachability Information)
    pub nlri: Vec<u8>,
    /// RIB entries with path identifiers
    pub entries: Vec<RIBEntryAddPath>,
}

impl RIB_GENERIC_ADDPATH {
    /// Parse a RIB_GENERIC_ADDPATH record.
    pub fn parse(stream: &mut impl Read) -> std::io::Result<Self> {
        let sequence_number = stream.read_u32::<BigEndian>()?;
        let afi = read_afi(stream)?;
        let safi = stream.read_u8()?;

        // NLRI is preceded by length
        let nlri_len = stream.read_u16::<BigEndian>()? as usize;
        let mut nlri = vec![0u8; nlri_len];
        stream.read_exact(&mut nlri)?;

        let entry_count = stream.read_u16::<BigEndian>()? as usize;
        let mut entries = Vec::with_capacity(entry_count);

        for _ in 0..entry_count {
            entries.push(RIBEntryAddPath::parse(stream)?);
        }

        Ok(RIB_GENERIC_ADDPATH {
            sequence_number,
            afi,
            safi,
            nlri,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_table_dump_ipv4() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 12,
            sub_type: 1, // AFI_IPv4
            length: 22,  // 2+2+4+1+1+4+4+2+2+0 = 22
        };
        let data: &[u8] = &[
            0x00, 0x00, // view_number = 0
            0x00, 0x01, // sequence_number = 1
            192, 168, 0, 0, // prefix
            0x18, // prefix_length = 24
            0x01, // status
            0x5F, 0x5E, 0x10, 0x00, // originated_time
            10, 0, 0, 1, // peer_address
            0x00, 0x64, // peer_as = 100
            0x00, 0x00, // attr_len = 0
        ];
        let result = TABLE_DUMP::parse(&header, &mut data.as_ref()).unwrap();
        assert_eq!(result.view_number, 0);
        assert_eq!(result.sequence_number, 1);
        assert_eq!(result.prefix, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(result.prefix_length, 24);
        assert_eq!(result.peer_address, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(result.peer_as, 100);
    }

    #[test]
    fn test_rib_ref_matches_owned_parse() {
        // RIB_IPV4_UNICAST body: sequence=1, /24 prefix 192.168.1, 2 entries
        let body: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, // sequence_number = 1
            24, // prefix_length = 24
            192, 168, 1, // prefix
            0x00, 0x02, // entry_count = 2
            // entry 0
            0x00, 0x05, // peer_index = 5
            0x5F, 0x5E, 0x10, 0x00, // originated_time
            0x00, 0x03, // attr_len = 3
            0xAA, 0xBB, 0xCC, // attributes
            // entry 1
            0x00, 0x06, // peer_index = 6
            0x5F, 0x5E, 0x10, 0x01, // originated_time
            0x00, 0x00, // attr_len = 0
        ];

        let owned = RIB_AFI::parse(&AFI::IPV4, &mut &body[..]).unwrap();
        let rib = RibRef::parse(AFI::IPV4, false, false, body).unwrap();

        assert_eq!(rib.sequence_number, owned.sequence_number);
        assert_eq!(rib.prefix_length, owned.prefix_length);
        assert_eq!(rib.prefix, &owned.prefix[..]);
        assert_eq!(rib.entry_count as usize, owned.entries.len());

        let entries: Vec<_> = rib.entries().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), owned.entries.len());
        for (r, o) in entries.iter().zip(&owned.entries) {
            assert_eq!(r.peer_index, o.peer_index);
            assert_eq!(r.originated_time, o.originated_time);
            assert_eq!(r.attributes, &o.attributes[..]);
            assert_eq!(r.path_id, None);
        }
    }

    #[test]
    fn test_rib_ref_addpath() {
        let body: &[u8] = &[
            0x00, 0x00, 0x00, 0x02, // sequence_number = 2
            16, // prefix_length = 16
            10, 0, // prefix
            0x00, 0x01, // entry_count = 1
            0x00, 0x07, // peer_index = 7
            0x5F, 0x5E, 0x10, 0x00, // originated_time
            0x00, 0x00, 0x00, 0x2A, // path_id = 42
            0x00, 0x02, // attr_len = 2
            0xDE, 0xAD, // attributes
        ];

        let rib = RibRef::parse(AFI::IPV4, false, true, body).unwrap();
        let entries: Vec<_> = rib.entries().map(|e| e.unwrap()).collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].peer_index, 7);
        assert_eq!(entries[0].path_id, Some(42));
        assert_eq!(entries[0].attributes, &[0xDE, 0xAD]);
    }

    #[test]
    fn test_rib_ref_truncated_entry() {
        let body: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, // sequence_number
            24, // prefix_length
            192, 168, 1, // prefix
            0x00, 0x01, // entry_count = 1
            0x00, 0x05, // peer_index (entry truncated after this)
        ];
        let rib = RibRef::parse(AFI::IPV4, false, false, body).unwrap();
        let mut iter = rib.entries();
        assert!(iter.next().unwrap().is_err());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_parse_peer_index_table() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 13,
            sub_type: 1, // PEER_INDEX_TABLE
            length: 100,
        };
        let data: &[u8] = &[
            0x0A, 0x00, 0x00, 0x01, // collector_id
            0x00, 0x04, // view_name_length = 4
            b't', b'e', b's', b't', // view_name = "test"
            0x00, 0x01, // peer_count = 1
            // Peer entry:
            0x00,       // peer_type = 0 (IPv4, 16-bit AS)
            0x0A, 0x00, 0x00, 0x01, // peer_bgp_id
            192, 168, 1, 1, // peer_ip_address (IPv4)
            0x00, 0x64, // peer_as = 100 (16-bit)
        ];
        let result = TABLE_DUMP_V2::parse(&header, &mut data.as_ref()).unwrap();
        match result {
            TABLE_DUMP_V2::PEER_INDEX_TABLE(pit) => {
                assert_eq!(pit.collector_id, 0x0A000001);
                assert_eq!(pit.view_name, "test");
                assert_eq!(pit.peer_entries.len(), 1);
                assert_eq!(pit.peer_entries[0].peer_as, 100);
                assert_eq!(
                    pit.peer_entries[0].peer_ip_address,
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
                );
            }
            _ => panic!("Expected PEER_INDEX_TABLE"),
        }
    }

    #[test]
    fn test_parse_rib_ipv4_unicast() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 13,
            sub_type: 2, // RIB_IPV4_UNICAST
            length: 100,
        };
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, // sequence_number = 1
            0x18, // prefix_length = 24
            192, 168, 1, // prefix (3 bytes for /24)
            0x00, 0x01, // entry_count = 1
            // RIB entry:
            0x00, 0x00, // peer_index = 0
            0x5F, 0x5E, 0x10, 0x00, // originated_time
            0x00, 0x00, // attr_len = 0
        ];
        let result = TABLE_DUMP_V2::parse(&header, &mut data.as_ref()).unwrap();
        match result {
            TABLE_DUMP_V2::RIB_IPV4_UNICAST(rib) => {
                assert_eq!(rib.sequence_number, 1);
                assert_eq!(rib.prefix_length, 24);
                assert_eq!(rib.prefix, vec![192, 168, 1]);
                assert_eq!(rib.entries.len(), 1);
                assert_eq!(rib.entries[0].peer_index, 0);
            }
            _ => panic!("Expected RIB_IPV4_UNICAST"),
        }
    }

    #[test]
    fn test_peer_type_flags() {
        // Test IPv6 + 32-bit AS
        // RFC 6396: bit 0 = IPv6 (1), bit 1 = AS4 (1) -> 0b11 = 0x03
        let data: &[u8] = &[
            0x03,       // peer_type = 0b11 (bit0=IPv6, bit1=AS4)
            0x0A, 0x00, 0x00, 0x01, // peer_bgp_id
            // IPv6 address: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x00, 0x01, 0x00, 0x00, // peer_as = 65536 (32-bit)
        ];
        let result = PeerEntry::parse(&mut data.as_ref()).unwrap();
        assert!(result.peer_ip_address.is_ipv6());
        assert_eq!(result.peer_as, 65536);
    }
}
