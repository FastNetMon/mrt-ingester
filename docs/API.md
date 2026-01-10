# mrt-rs API/ABI reference

This document describes the public API surface of `mrt-rs` as it exists in this repository.
The goal is to help implement a compatible library with the same API/ABI behavior.

Notes:
- The crate is Rust-native; ABI stability is **not** guaranteed for most types because they do not
  use `repr(C)` (except `AFI`, which is `repr(u16)`). If you need ABI compatibility, match
  field order and Rust ABI expectations exactly for the same compiler/version.
- All parsing functions read from a stream and return `std::io::Result<T>`; they do not use unsafe
  code and generally return `ErrorKind::Other` or `ErrorKind::InvalidData` on invalid input.

## ABI compatibility checklist

- Pin the Rust toolchain version and target triple to match your intended consumers.
- Keep all public type names, modules, and re-exports identical (paths matter for Rust users).
- Match enum variant order and struct field order exactly as declared here.
- Do not add `repr(C)` unless you also match the original layout decisions; it changes layout.
- Preserve integer sizes (`u16`, `u32`, `u8`) and `std::net` address types exactly.
- Use the same error kinds and return types (`std::io::Result`, `Option`).
- Avoid feature flags that alter public signatures or type layouts unless you keep defaults identical.
- If you expose a C ABI, put it behind separate `extern "C"` wrappers so the Rust API stays intact.

## Minimal compatible crate skeleton (example)

This skeleton shows the public shape only; fill in parsing logic to match behavior.

```
compat-mrt/
  Cargo.toml
  src/
    lib.rs
    records/
      bgp.rs
      bgp4plus.rs
      bgp4mp.rs
      isis.rs
      ospf.rs
      rip.rs
      tabledump.rs
```

`Cargo.toml`:
```toml
[package]
name = "mrt_rs"
version = "0.0.0"
edition = "2018"

[dependencies]
byteorder = "1"
```

`src/lib.rs` (public API surface only):
```rust
#![deny(missing_docs)]

use std::io::{Error, Read};

pub mod records {
    pub mod bgp;
    pub mod bgp4plus;
    pub mod bgp4mp;
    pub mod isis;
    pub mod ospf;
    pub mod rip;
    pub mod tabledump;
}

pub use records::bgp;
pub use records::bgp4mp;
pub use records::bgp4plus;
pub use records::isis;
pub use records::ospf;
pub use records::rip;
pub use records::tabledump;

#[derive(Debug)]
#[repr(u16)]
pub enum AFI {
    IPV4 = 1,
    IPV6 = 2,
}

impl AFI {
    pub fn size(&self) -> u32 {
        match self {
            AFI::IPV4 => 4,
            AFI::IPV6 => 16,
        }
    }
}

#[derive(Debug)]
pub struct Header {
    pub timestamp: u32,
    pub extended: u32,
    pub record_type: u16,
    pub sub_type: u16,
    pub length: u32,
}

#[derive(Debug)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum Record {
    NULL,
    START,
    DIE,
    I_AM_DEAD,
    PEER_DOWN,
    BGP(records::bgp::BGP),
    RIP(records::rip::RIP),
    IDRP,
    RIPNG(records::rip::RIPNG),
    BGP4PLUS(records::bgp4plus::BGP4PLUS),
    BGP4PLUS_01(records::bgp4plus::BGP4PLUS),
    OSPFv2(records::ospf::OSPFv2),
    TABLE_DUMP(records::tabledump::TABLE_DUMP),
    TABLE_DUMP_V2(records::tabledump::TABLE_DUMP_V2),
    BGP4MP(records::bgp4mp::BGP4MP),
    BGP4MP_ET(records::bgp4mp::BGP4MP),
    ISIS(Vec<u8>),
    ISIS_ET(Vec<u8>),
    OSPFv3(records::ospf::OSPFv3),
    OSPFv3_ET(records::ospf::OSPFv3),
}

pub fn read(_stream: &mut impl Read) -> Result<Option<(Header, Record)>, Error> {
    unimplemented!("parse MRT records and return Header + Record")
}
```

## Crate root: `mrt_rs`

### Modules (public)
- `mrt_rs::records`
  - `mrt_rs::records::bgp`
  - `mrt_rs::records::bgp4plus`
  - `mrt_rs::records::bgp4mp`
  - `mrt_rs::records::isis`
  - `mrt_rs::records::ospf`
  - `mrt_rs::records::rip`
  - `mrt_rs::records::tabledump`

The following modules are re-exported at the crate root for convenience:
- `mrt_rs::bgp`
- `mrt_rs::bgp4plus`
- `mrt_rs::bgp4mp`
- `mrt_rs::isis`
- `mrt_rs::ospf`
- `mrt_rs::rip`
- `mrt_rs::tabledump`

### Enums and structs

#### `enum AFI` (`repr(u16)`)
Represents Address Family Identifier.
- Variants:
  - `AFI::IPV4 = 1`
  - `AFI::IPV6 = 2`
- Methods:
  - `pub fn size(&self) -> u32`
    - Returns 4 for `IPV4`, 16 for `IPV6`.

#### `struct Header`
Represents the MRT header that precedes every record.
- Fields:
  - `pub timestamp: u32` (UNIX seconds)
  - `pub extended: u32` (microsecond resolution, 0 if not present)
  - `pub record_type: u16`
  - `pub sub_type: u16`
  - `pub length: u32` (payload length, excluding header)

#### `enum Record`
Represents a fully-parsed MRT record.
- Variants:
  - `NULL`
  - `START`
  - `DIE`
  - `I_AM_DEAD`
  - `PEER_DOWN`
  - `BGP(mrt_rs::records::bgp::BGP)`
  - `RIP(mrt_rs::records::rip::RIP)`
  - `IDRP`
  - `RIPNG(mrt_rs::records::rip::RIPNG)`
  - `BGP4PLUS(mrt_rs::records::bgp4plus::BGP4PLUS)`
  - `BGP4PLUS_01(mrt_rs::records::bgp4plus::BGP4PLUS)`
  - `OSPFv2(mrt_rs::records::ospf::OSPFv2)`
  - `TABLE_DUMP(mrt_rs::records::tabledump::TABLE_DUMP)`
  - `TABLE_DUMP_V2(mrt_rs::records::tabledump::TABLE_DUMP_V2)`
  - `BGP4MP(mrt_rs::records::bgp4mp::BGP4MP)`
  - `BGP4MP_ET(mrt_rs::records::bgp4mp::BGP4MP)`
  - `ISIS(Vec<u8>)`
  - `ISIS_ET(Vec<u8>)`
  - `OSPFv3(mrt_rs::records::ospf::OSPFv3)`
  - `OSPFv3_ET(mrt_rs::records::ospf::OSPFv3)`

### Functions

#### `pub fn read(stream: &mut impl std::io::Read) -> std::io::Result<Option<(Header, Record)>>`
Reads the next MRT record from the stream.
- Returns `Ok(None)` on EOF at the beginning of a record.
- Returns `Ok(Some((header, record)))` on success.
- For unknown/unsupported types it returns an `std::io::Error`.

## Module: `mrt_rs::records::bgp`

### `enum BGP`
- Variants:
  - `NULL`
  - `UPDATE(MESSAGE)`
  - `PREF_UPDATE`
  - `STATE_CHANGE(STATE_CHANGE)`
  - `SYNC(SYNC)`
  - `OPEN(MESSAGE)`
  - `NOTIFY(MESSAGE)`
  - `KEEPALIVE(MESSAGE)`

### `struct MESSAGE`
Represents BGP UPDATE/OPEN/NOTIFY/KEEPALIVE for IPv4 peers (deprecated MRT type).
- Fields:
  - `pub peer_as: u16`
  - `pub peer_ip: std::net::Ipv4Addr`
  - `pub local_as: u16`
  - `pub local_ip: std::net::Ipv4Addr`
  - `pub message: Vec<u8>`

### `struct STATE_CHANGE`
- Fields:
  - `pub peer_as: u16`
  - `pub peer_ip: std::net::Ipv4Addr`
  - `pub old_state: u16`
  - `pub new_state: u16`

### `struct SYNC`
Deprecated RIB recording pointer.
- Fields:
  - `pub view_number: u16`
  - `pub filename: Vec<u8>` (NULL-terminated bytes in the file format)

## Module: `mrt_rs::records::bgp4plus`

### `enum BGP4PLUS`
- Variants:
  - `NULL`
  - `UPDATE(MESSAGE)`
  - `PREF_UPDATE`
  - `STATE_CHANGE(STATE_CHANGE)`
  - `SYNC(SYNC)`
  - `OPEN(MESSAGE)`
  - `NOTIFY(MESSAGE)`
  - `KEEPALIVE(MESSAGE)`

### `struct MESSAGE`
Represents BGP UPDATE/OPEN/NOTIFY/KEEPALIVE for IPv6 peers (deprecated MRT type).
- Fields:
  - `pub peer_as: u16`
  - `pub peer_ip: std::net::Ipv6Addr`
  - `pub local_as: u16`
  - `pub local_ip: std::net::Ipv6Addr`
  - `pub message: Vec<u8>`

### `struct STATE_CHANGE`
- Fields:
  - `pub peer_as: u16`
  - `pub peer_ip: std::net::Ipv6Addr`
  - `pub old_state: u16`
  - `pub new_state: u16`

### `struct SYNC`
Deprecated RIB recording pointer.
- Fields:
  - `pub view_number: u16`
  - `pub filename: Vec<u8>` (NULL-terminated bytes in the file format)

## Module: `mrt_rs::records::bgp4mp`

### `enum BGP4MP`
- Variants:
  - `STATE_CHANGE(STATE_CHANGE)`
  - `MESSAGE(MESSAGE)`
  - `ENTRY(ENTRY)`
  - `SNAPSHOT(SNAPSHOT)`
  - `MESSAGE_AS4(MESSAGE_AS4)`
  - `STATE_CHANGE_AS4(STATE_CHANGE_AS4)`
  - `MESSAGE_LOCAL(MESSAGE)`
  - `MESSAGE_AS4_LOCAL(MESSAGE_AS4)`
  - `MESSAGE_ADDPATH(MESSAGE)`
  - `MESSAGE_AS4_ADDPATH(MESSAGE_AS4)`
  - `MESSAGE_LOCAL_ADDPATH(MESSAGE)`
  - `MESSAGE_AS4_LOCAL_ADDPATH(MESSAGE_AS4)`

### `struct STATE_CHANGE`
16-bit ASN state change.
- Fields:
  - `pub peer_as: u16`
  - `pub local_as: u16`
  - `pub interface: u16`
  - `pub peer_address: std::net::IpAddr`
  - `pub local_address: std::net::IpAddr`
  - `pub old_state: u16`
  - `pub new_state: u16`

### `struct MESSAGE`
16-bit ASN BGP message.
- Fields:
  - `pub peer_as: u16`
  - `pub local_as: u16`
  - `pub interface: u16`
  - `pub peer_address: std::net::IpAddr`
  - `pub local_address: std::net::IpAddr`
  - `pub message: Vec<u8>`

### `struct MESSAGE_AS4`
32-bit ASN BGP message.
- Fields:
  - `pub peer_as: u32`
  - `pub local_as: u32`
  - `pub interface: u16`
  - `pub peer_address: std::net::IpAddr`
  - `pub local_address: std::net::IpAddr`
  - `pub message: Vec<u8>`

### `struct STATE_CHANGE_AS4`
32-bit ASN state change.
- Fields:
  - `pub peer_as: u32`
  - `pub local_as: u32`
  - `pub interface: u16`
  - `pub peer_address: std::net::IpAddr`
  - `pub local_address: std::net::IpAddr`
  - `pub old_state: u16`
  - `pub new_state: u16`

### `struct SNAPSHOT`
Deprecated snapshot pointer.
- Fields:
  - `pub view_number: u16`
  - `pub filename: Vec<u8>` (NULL-terminated bytes in the file format)

### `struct ENTRY`
Deprecated RIB entry format.
- Fields:
  - `pub peer_as: u16`
  - `pub local_as: u16`
  - `pub interface: u16`
  - `pub peer_address: std::net::IpAddr`
  - `pub local_address: std::net::IpAddr`
  - `pub view_number: u16`
  - `pub status: u16`
  - `pub time_last_change: u32`
  - `pub next_hop: std::net::IpAddr`
  - `pub afi: u16`
  - `pub safi: u8`
  - `pub prefix_length: u8`
  - `pub prefix: Vec<u8>`
  - `pub attributes: Vec<u8>`

## Module: `mrt_rs::records::tabledump`

### `struct TABLE_DUMP`
Represents a TABLE_DUMP record (RIB entry).
- Fields:
  - `pub view_number: u16`
  - `pub sequence_number: u16`
  - `pub prefix: std::net::IpAddr`
  - `pub prefix_length: u8`
  - `pub status: u8`
  - `pub originated_time: u32`
  - `pub peer_address: std::net::IpAddr`
  - `pub peer_as: u16`
  - `pub attributes: Vec<u8>`
- Methods:
  - `pub fn parse(header: &Header, stream: impl std::io::Read) -> std::io::Result<TABLE_DUMP>`

### `enum TABLE_DUMP_V2`
Represents TABLE_DUMP_V2 and RFC8050 Add-Path variants.
- Variants:
  - `PEER_INDEX_TABLE(PEER_INDEX_TABLE)`
  - `RIB_IPV4_UNICAST(RIB_AFI)`
  - `RIB_IPV4_MULTICAST(RIB_AFI)`
  - `RIB_IPV6_UNICAST(RIB_AFI)`
  - `RIB_IPV6_MULTICAST(RIB_AFI)`
  - `RIB_GENERIC(RIB_GENERIC)`
  - `RIB_IPV4_UNICAST_ADDPATH(RIB_AFI_ADDPATH)`
  - `RIB_IPV4_MULTICAST_ADDPATH(RIB_AFI_ADDPATH)`
  - `RIB_IPV6_UNICAST_ADDPATH(RIB_AFI_ADDPATH)`
  - `RIB_IPV6_MULTICAST_ADDPATH(RIB_AFI_ADDPATH)`
  - `RIB_GENERIC_ADDPATH(RIB_GENERIC_ADDPATH)`
- Methods:
  - `pub fn parse(header: &Header, stream: impl std::io::Read) -> std::io::Result<TABLE_DUMP_V2>`

### `struct PEER_INDEX_TABLE`
- Fields:
  - `pub collector_id: u32`
  - `pub view_name: String`
  - `pub peer_entries: Vec<PeerEntry>`

### `struct PeerEntry`
- Fields:
  - `pub peer_type: u8`
  - `pub peer_bgp_id: u32`
  - `pub peer_ip_address: std::net::IpAddr`
  - `pub peer_as: u32`

### `struct RIBEntry`
- Fields:
  - `pub peer_index: u16`
  - `pub originated_time: u32`
  - `pub attributes: Vec<u8>`

### `struct RIB_AFI`
- Fields:
  - `pub sequence_number: u32`
  - `pub prefix_length: u8`
  - `pub prefix: Vec<u8>`
  - `pub entries: Vec<RIBEntry>`

### `struct RIB_GENERIC`
- Fields:
  - `pub sequence_number: u32`
  - `pub afi: AFI`
  - `pub safi: u8`
  - `pub nlri: Vec<u8>`
  - `pub entries: Vec<RIBEntry>`

### `struct RIBEntryAddPath`
- Fields:
  - `pub peer_index: u16`
  - `pub originated_time: u32`
  - `pub path_identifier: u32`
  - `pub attributes: Vec<u8>`

### `struct RIB_AFI_ADDPATH`
- Fields:
  - `pub sequence_number: u32`
  - `pub prefix_length: u8`
  - `pub prefix: Vec<u8>`
  - `pub entries: Vec<RIBEntryAddPath>`

### `struct RIB_GENERIC_ADDPATH`
- Fields:
  - `pub sequence_number: u32`
  - `pub afi: AFI`
  - `pub safi: u8`
  - `pub nlri: Vec<u8>`
  - `pub entries: Vec<RIBEntryAddPath>`

## Module: `mrt_rs::records::rip`

### `struct RIP`
- Fields:
  - `pub remote: std::net::Ipv4Addr`
  - `pub local: std::net::Ipv4Addr`
  - `pub message: Vec<u8>`
- Methods:
  - `pub fn parse(header: &Header, stream: impl std::io::Read) -> std::io::Result<RIP>`

### `struct RIPNG`
- Fields:
  - `pub remote: std::net::Ipv6Addr`
  - `pub local: std::net::Ipv6Addr`
  - `pub message: Vec<u8>`
- Methods:
  - `pub fn parse(header: &Header, stream: impl std::io::Read) -> std::io::Result<RIPNG>`

## Module: `mrt_rs::records::ospf`

### `struct OSPFv2`
- Fields:
  - `pub remote: std::net::Ipv4Addr`
  - `pub local: std::net::Ipv4Addr`
  - `pub message: Vec<u8>`
- Methods:
  - `pub fn parse(header: &Header, stream: impl std::io::Read) -> std::io::Result<OSPFv2>`

### `struct OSPFv3`
- Fields:
  - `pub remote: std::net::IpAddr`
  - `pub local: std::net::IpAddr`
  - `pub message: Vec<u8>`
- Methods:
  - `pub fn parse(header: &Header, stream: impl std::io::Read) -> std::io::Result<OSPFv3>`

## Module: `mrt_rs::records::isis`

### `fn parse`
- Signature: `pub fn parse(header: &Header, stream: impl std::io::Read) -> std::io::Result<Vec<u8>>`
- Behavior: reads exactly `header.length` bytes and returns them as a `Vec<u8>`.

## Behavior notes

- `read` interprets `record_type` values as:
  - 0 NULL, 1 START, 2 DIE, 3 I_AM_DEAD, 4 PEER_DOWN,
  - 5 BGP, 6 RIP, 7 IDRP, 8 RIPNG, 9 BGP4PLUS, 10 BGP4PLUS_01,
  - 11 OSPFv2, 12 TABLE_DUMP, 13 TABLE_DUMP_V2, 16 BGP4MP, 17 BGP4MP_ET,
  - 32 ISIS, 33 ISIS_ET, 48 OSPFv3, 49 OSPFv3_ET.
- `Header.extended` is set only for the `*_ET` record types: `BGP4MP_ET` (17), `ISIS_ET` (33),
  and `OSPFv3_ET` (49). For all other record types it remains 0.
- All parsing is big-endian and consumes exactly `header.length` bytes for the record body
  (except where noted by record format definition).
