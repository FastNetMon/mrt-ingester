# mrt_rs

High-performance parser for MRT (Multi-threaded Routing Toolkit) routing data files.

## Overview

This library parses MRT-formatted binary streams containing BGP routing information, as specified in RFC 6396 and RFC 8050.

## Features

- Full support for all MRT record types defined in RFC 6396
- BGP Add-Path extensions (RFC 8050)
- Zero-copy design where possible
- API-compatible with the original `mrt-rs` crate

## Supported Record Types

| Type | Name | Description |
|------|------|-------------|
| 5 | BGP | Legacy BGP records (IPv4, 16-bit ASN) |
| 6 | RIP | RIP protocol records |
| 8 | RIPNG | RIPng protocol records |
| 9-10 | BGP4PLUS | Legacy BGP records (IPv6, 16-bit ASN) |
| 11 | OSPFv2 | OSPFv2 protocol records |
| 12 | TABLE_DUMP | RIB dump (one entry per record) |
| 13 | TABLE_DUMP_V2 | RIB dump v2 (multiple entries per record) |
| 16-17 | BGP4MP | Modern BGP records (IPv4/IPv6, 16/32-bit ASN) |
| 32-33 | ISIS | IS-IS protocol records |
| 48-49 | OSPFv3 | OSPFv3 protocol records |

## Usage

```rust
use std::fs::File;
use std::io::BufReader;

fn main() -> std::io::Result<()> {
    let file = File::open("updates.mrt")?;
    let mut reader = BufReader::new(file);

    while let Some((header, record)) = mrt_rs::read(&mut reader)? {
        println!("Timestamp: {}, Type: {}", header.timestamp, header.record_type);

        match record {
            mrt_rs::Record::BGP4MP(bgp4mp) => {
                // Handle BGP4MP record
            }
            mrt_rs::Record::TABLE_DUMP_V2(table_dump) => {
                // Handle TABLE_DUMP_V2 record
            }
            _ => {}
        }
    }

    Ok(())
}
```

## Data Sources

MRT files are available from:

- [RouteViews Archive](http://archive.routeviews.org/)
- [RIPE RIS Raw Data](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## References

- [RFC 6396](https://datatracker.ietf.org/doc/html/rfc6396) - MRT Routing Information Export Format
- [RFC 8050](https://datatracker.ietf.org/doc/html/rfc8050) - MRT with BGP Additional Path Extensions
