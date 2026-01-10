//! # mrt_rs
//!
//! High-performance parser for MRT (Multi-threaded Routing Toolkit) routing data files.
//!
//! This crate provides types and functions to parse MRT-formatted binary streams
//! containing BGP routing information, as specified in RFC 6396 and RFC 8050.
//!
//! ## Example
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufReader;
//!
//! let file = File::open("updates.mrt").unwrap();
//! let mut reader = BufReader::new(file);
//!
//! while let Some((header, record)) = mrt_rs::read(&mut reader).unwrap() {
//!     println!("Record type: {}, timestamp: {}", header.record_type, header.timestamp);
//! }
//! ```

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};

pub mod records;

// Re-export record modules at crate root for API compatibility
pub use records::bgp;
pub use records::bgp4mp;
pub use records::bgp4plus;
pub use records::isis;
pub use records::ospf;
pub use records::rip;
pub use records::tabledump;

/// Address Family Identifier (AFI) as defined in RFC 4760.
///
/// Used to distinguish between IPv4 and IPv6 address families in MRT records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum AFI {
    /// IPv4 address family (AFI = 1)
    IPV4 = 1,
    /// IPv6 address family (AFI = 2)
    IPV6 = 2,
}

impl AFI {
    /// Returns the size in bytes of addresses for this address family.
    ///
    /// - `IPV4` returns 4
    /// - `IPV6` returns 16
    #[inline]
    pub fn size(&self) -> u32 {
        match self {
            AFI::IPV4 => 4,
            AFI::IPV6 => 16,
        }
    }

    /// Parse an AFI value from a 16-bit integer.
    #[inline]
    pub(crate) fn from_u16(value: u16) -> std::io::Result<Self> {
        match value {
            1 => Ok(AFI::IPV4),
            2 => Ok(AFI::IPV6),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                format!("invalid AFI value: {}", value),
            )),
        }
    }
}

/// MRT record header that precedes every record.
///
/// The header contains metadata about the record including timestamp,
/// type information, and payload length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// UNIX timestamp (seconds since epoch)
    pub timestamp: u32,
    /// Extended timestamp in microseconds (only set for *_ET record types, otherwise 0)
    pub extended: u32,
    /// Record type identifier
    pub record_type: u16,
    /// Record subtype identifier
    pub sub_type: u16,
    /// Length of the record payload in bytes (excluding header)
    pub length: u32,
}

/// Fully-parsed MRT record.
///
/// Each variant corresponds to a specific MRT record type as defined in RFC 6396.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum Record {
    /// Null record (type 0)
    NULL,
    /// Start record (type 1)
    START,
    /// Die record (type 2)
    DIE,
    /// I am dead record (type 3)
    I_AM_DEAD,
    /// Peer down record (type 4)
    PEER_DOWN,
    /// Legacy BGP record (type 5) - deprecated
    BGP(records::bgp::BGP),
    /// RIP record (type 6)
    RIP(records::rip::RIP),
    /// IDRP record (type 7) - reserved
    IDRP,
    /// RIPng record (type 8)
    RIPNG(records::rip::RIPNG),
    /// BGP4+ record (type 9) - deprecated
    BGP4PLUS(records::bgp4plus::BGP4PLUS),
    /// BGP4+ record variant (type 10) - deprecated
    BGP4PLUS_01(records::bgp4plus::BGP4PLUS),
    /// OSPFv2 record (type 11)
    OSPFv2(records::ospf::OSPFv2),
    /// TABLE_DUMP record (type 12)
    TABLE_DUMP(records::tabledump::TABLE_DUMP),
    /// TABLE_DUMP_V2 record (type 13)
    TABLE_DUMP_V2(records::tabledump::TABLE_DUMP_V2),
    /// BGP4MP record (type 16)
    BGP4MP(records::bgp4mp::BGP4MP),
    /// BGP4MP with extended timestamp (type 17)
    BGP4MP_ET(records::bgp4mp::BGP4MP),
    /// IS-IS record (type 32)
    ISIS(Vec<u8>),
    /// IS-IS with extended timestamp (type 33)
    ISIS_ET(Vec<u8>),
    /// OSPFv3 record (type 48)
    OSPFv3(records::ospf::OSPFv3),
    /// OSPFv3 with extended timestamp (type 49)
    OSPFv3_ET(records::ospf::OSPFv3),
}

/// Record type constants
mod record_types {
    pub const NULL: u16 = 0;
    pub const START: u16 = 1;
    pub const DIE: u16 = 2;
    pub const I_AM_DEAD: u16 = 3;
    pub const PEER_DOWN: u16 = 4;
    pub const BGP: u16 = 5;
    pub const RIP: u16 = 6;
    pub const IDRP: u16 = 7;
    pub const RIPNG: u16 = 8;
    pub const BGP4PLUS: u16 = 9;
    pub const BGP4PLUS_01: u16 = 10;
    pub const OSPFV2: u16 = 11;
    pub const TABLE_DUMP: u16 = 12;
    pub const TABLE_DUMP_V2: u16 = 13;
    pub const BGP4MP: u16 = 16;
    pub const BGP4MP_ET: u16 = 17;
    pub const ISIS: u16 = 32;
    pub const ISIS_ET: u16 = 33;
    pub const OSPFV3: u16 = 48;
    pub const OSPFV3_ET: u16 = 49;
}

/// Check if a record type uses extended timestamp format.
#[inline]
fn is_extended_type(record_type: u16) -> bool {
    matches!(
        record_type,
        record_types::BGP4MP_ET | record_types::ISIS_ET | record_types::OSPFV3_ET
    )
}

/// Reads the next MRT record from the stream.
///
/// # Returns
///
/// - `Ok(None)` - EOF reached at the beginning of a record (clean end of file)
/// - `Ok(Some((header, record)))` - Successfully parsed a record
/// - `Err(e)` - I/O error or invalid/unsupported record format
///
/// # Errors
///
/// Returns an error if:
/// - The stream contains invalid data
/// - An unknown or unsupported record type is encountered
/// - EOF is reached in the middle of a record
///
/// # Example
///
/// ```no_run
/// use std::io::Cursor;
///
/// let data: &[u8] = &[/* MRT binary data */];
/// let mut cursor = Cursor::new(data);
///
/// while let Some((header, record)) = mrt_rs::read(&mut cursor).unwrap() {
///     // Process record
/// }
/// ```
pub fn read(stream: &mut impl Read) -> Result<Option<(Header, Record)>, Error> {
    // Read timestamp (4 bytes) - EOF here is clean end of stream
    let timestamp = match stream.read_u32::<BigEndian>() {
        Ok(ts) => ts,
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };

    // Read remaining header fields - EOF here is an error
    let record_type = stream.read_u16::<BigEndian>()?;
    let sub_type = stream.read_u16::<BigEndian>()?;
    let length = stream.read_u32::<BigEndian>()?;

    // Handle extended timestamp for *_ET types
    let (extended, body_length) = if is_extended_type(record_type) {
        let microseconds = stream.read_u32::<BigEndian>()?;
        // Extended types include microseconds in length, subtract it for body
        (microseconds, length.saturating_sub(4))
    } else {
        (0, length)
    };

    let header = Header {
        timestamp,
        extended,
        record_type,
        sub_type,
        length,
    };

    // Read exact body into buffer
    let mut body = vec![0u8; body_length as usize];
    stream.read_exact(&mut body)?;

    // Parse record based on type
    let record = parse_record(&header, &body)?;

    Ok(Some((header, record)))
}

/// Parse record body into appropriate Record variant.
fn parse_record(header: &Header, body: &[u8]) -> Result<Record, Error> {
    use record_types::*;

    let mut cursor = std::io::Cursor::new(body);

    match header.record_type {
        NULL => Ok(Record::NULL),
        START => Ok(Record::START),
        DIE => Ok(Record::DIE),
        I_AM_DEAD => Ok(Record::I_AM_DEAD),
        PEER_DOWN => Ok(Record::PEER_DOWN),
        BGP => Ok(Record::BGP(records::bgp::BGP::parse(header, &mut cursor)?)),
        RIP => Ok(Record::RIP(records::rip::RIP::parse(header, &mut cursor)?)),
        IDRP => Ok(Record::IDRP),
        RIPNG => Ok(Record::RIPNG(records::rip::RIPNG::parse(
            header,
            &mut cursor,
        )?)),
        BGP4PLUS => Ok(Record::BGP4PLUS(records::bgp4plus::BGP4PLUS::parse(
            header,
            &mut cursor,
        )?)),
        BGP4PLUS_01 => Ok(Record::BGP4PLUS_01(records::bgp4plus::BGP4PLUS::parse(
            header,
            &mut cursor,
        )?)),
        OSPFV2 => Ok(Record::OSPFv2(records::ospf::OSPFv2::parse(
            header,
            &mut cursor,
        )?)),
        TABLE_DUMP => Ok(Record::TABLE_DUMP(records::tabledump::TABLE_DUMP::parse(
            header,
            &mut cursor,
        )?)),
        TABLE_DUMP_V2 => Ok(Record::TABLE_DUMP_V2(
            records::tabledump::TABLE_DUMP_V2::parse(header, &mut cursor)?,
        )),
        BGP4MP => Ok(Record::BGP4MP(records::bgp4mp::BGP4MP::parse(
            header,
            &mut cursor,
        )?)),
        BGP4MP_ET => Ok(Record::BGP4MP_ET(records::bgp4mp::BGP4MP::parse(
            header,
            &mut cursor,
        )?)),
        ISIS => Ok(Record::ISIS(records::isis::parse(header, &mut cursor)?)),
        ISIS_ET => Ok(Record::ISIS_ET(records::isis::parse(header, &mut cursor)?)),
        OSPFV3 => Ok(Record::OSPFv3(records::ospf::OSPFv3::parse(
            header,
            &mut cursor,
        )?)),
        OSPFV3_ET => Ok(Record::OSPFv3_ET(records::ospf::OSPFv3::parse(
            header,
            &mut cursor,
        )?)),
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            format!("unknown record type: {}", header.record_type),
        )),
    }
}

/// Internal helper module for address parsing.
pub(crate) mod address {
    use byteorder::{BigEndian, ReadBytesExt};
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::AFI;

    /// Read an IPv4 address from the stream.
    #[inline]
    pub fn read_ipv4(stream: &mut impl Read) -> std::io::Result<Ipv4Addr> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        Ok(Ipv4Addr::from(buf))
    }

    /// Read an IPv6 address from the stream.
    #[inline]
    pub fn read_ipv6(stream: &mut impl Read) -> std::io::Result<Ipv6Addr> {
        let mut buf = [0u8; 16];
        stream.read_exact(&mut buf)?;
        Ok(Ipv6Addr::from(buf))
    }

    /// Read an IP address based on AFI.
    #[inline]
    pub fn read_ip_by_afi(stream: &mut impl Read, afi: &AFI) -> std::io::Result<IpAddr> {
        match afi {
            AFI::IPV4 => Ok(IpAddr::V4(read_ipv4(stream)?)),
            AFI::IPV6 => Ok(IpAddr::V6(read_ipv6(stream)?)),
        }
    }

    /// Read an AFI value from the stream.
    #[inline]
    pub fn read_afi(stream: &mut impl Read) -> std::io::Result<AFI> {
        let afi_raw = stream.read_u16::<BigEndian>()?;
        AFI::from_u16(afi_raw)
    }

    /// Calculate the number of bytes needed to store a prefix of given length.
    #[inline]
    pub fn prefix_bytes_needed(prefix_length: u8) -> usize {
        ((prefix_length as usize) + 7) / 8
    }

    /// Read a prefix of the given bit length.
    #[inline]
    pub fn read_prefix(stream: &mut impl Read, prefix_length: u8) -> std::io::Result<Vec<u8>> {
        let bytes_needed = prefix_bytes_needed(prefix_length);
        let mut prefix = vec![0u8; bytes_needed];
        stream.read_exact(&mut prefix)?;
        Ok(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_afi_size() {
        assert_eq!(AFI::IPV4.size(), 4);
        assert_eq!(AFI::IPV6.size(), 16);
    }

    #[test]
    fn test_afi_repr() {
        assert_eq!(std::mem::size_of::<AFI>(), 2);
        assert_eq!(AFI::IPV4 as u16, 1);
        assert_eq!(AFI::IPV6 as u16, 2);
    }

    #[test]
    fn test_read_eof_at_start() {
        let data: &[u8] = &[];
        let result = read(&mut data.as_ref());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_read_null_record() {
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, // timestamp = 1
            0x00, 0x00, // type = 0 (NULL)
            0x00, 0x00, // subtype = 0
            0x00, 0x00, 0x00, 0x00, // length = 0
        ];
        let result = read(&mut data.as_ref()).unwrap().unwrap();
        assert_eq!(result.0.timestamp, 1);
        assert!(matches!(result.1, Record::NULL));
    }

    #[test]
    fn test_read_start_record() {
        let data: &[u8] = &[
            0x5F, 0x5E, 0x10, 0x00, // timestamp
            0x00, 0x01, // type = 1 (START)
            0x00, 0x00, // subtype = 0
            0x00, 0x00, 0x00, 0x00, // length = 0
        ];
        let result = read(&mut data.as_ref()).unwrap().unwrap();
        assert!(matches!(result.1, Record::START));
    }

    #[test]
    fn test_read_unknown_type_error() {
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, // timestamp
            0x00, 0xFF, // type = 255 (unknown)
            0x00, 0x00, // subtype
            0x00, 0x00, 0x00, 0x00, // length = 0
        ];
        let result = read(&mut data.as_ref());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn test_is_extended_type() {
        assert!(!is_extended_type(16)); // BGP4MP
        assert!(is_extended_type(17)); // BGP4MP_ET
        assert!(!is_extended_type(32)); // ISIS
        assert!(is_extended_type(33)); // ISIS_ET
        assert!(!is_extended_type(48)); // OSPFv3
        assert!(is_extended_type(49)); // OSPFv3_ET
    }
}
