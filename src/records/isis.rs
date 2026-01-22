// SPDX-License-Identifier: MIT OR Apache-2.0

//! IS-IS protocol MRT record parsing.
//!
//! IS-IS records contain raw IS-IS protocol data units (PDUs).

use crate::Header;
use std::io::Read;

/// Parse an IS-IS record, returning the raw PDU bytes.
///
/// IS-IS records simply contain the raw IS-IS PDU without additional framing.
/// The entire record body is returned as a byte vector.
///
/// # Arguments
///
/// * `header` - The MRT record header (used to determine body length)
/// * `stream` - The input stream positioned at the record body
///
/// # Returns
///
/// The raw IS-IS PDU bytes.
pub fn parse(header: &Header, stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    // For extended types, the length field includes the 4-byte microseconds
    // which has already been read, so we need to calculate actual body length
    let body_length = if header.record_type == 33 {
        // ISIS_ET
        header.length.saturating_sub(4)
    } else {
        header.length
    };

    let mut data = vec![0u8; body_length as usize];
    stream.read_exact(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_isis() {
        let header = Header {
            timestamp: 1000,
            extended: 0,
            record_type: 32,
            sub_type: 0,
            length: 10,
        };
        let data: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let result = parse(&header, &mut data.as_ref()).unwrap();
        assert_eq!(result.len(), 10);
        assert_eq!(result, data);
    }
}
