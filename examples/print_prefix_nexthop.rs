// SPDX-License-Identifier: MIT OR Apache-2.0

//! Print `prefix/len -> nexthop` for every route in an MRT RIB dump.
//!
//! Handles the formats produced by RouteViews and RIPE RIS:
//! - TABLE_DUMP_V2 (type 13) — modern RIB dumps
//! - TABLE_DUMP    (type 12) — legacy RIB dumps
//!
//! Plain and gzip-compressed (`.gz`) files are both accepted — detection is
//! by magic bytes, so a misnamed file still works.
//!
//! Usage:
//!     cargo run --release --example print_prefix_nexthop -- <file.mrt[.gz]>
//!
//! The next hop sits inside a BGP path attribute, which `mrt_ingester` exposes
//! as raw bytes (`attributes: Vec<u8>`). We walk those bytes here:
//!   - IPv4 RIBs:  NEXT_HOP attribute (type 3, RFC 4271)
//!   - IPv6 RIBs:  MP_REACH_NLRI attribute (type 14, RFC 4760),
//!                 compressed per RFC 6396 §4.3.4 to `len + nexthop` only.

use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mrt_ingester::records::tabledump::{TABLE_DUMP, TABLE_DUMP_V2, RIB_AFI};
use mrt_ingester::{Record, AFI};

fn main() -> std::io::Result<()> {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: print_prefix_nexthop <file.mrt[.gz]>");
        std::process::exit(2);
    });

    let mut reader = mrt_ingester::open(&path)?;

    while let Some((_header, record)) = mrt_ingester::read(&mut reader)? {
        match record {
            Record::TABLE_DUMP_V2(v2) => handle_v2(v2),
            Record::TABLE_DUMP(td) => handle_v1(td),
            _ => {}
        }
    }

    Ok(())
}

fn handle_v2(v2: TABLE_DUMP_V2) {
    match v2 {
        TABLE_DUMP_V2::RIB_IPV4_UNICAST(rib) | TABLE_DUMP_V2::RIB_IPV4_MULTICAST(rib) => {
            print_rib(&rib, AFI::IPV4);
        }
        TABLE_DUMP_V2::RIB_IPV6_UNICAST(rib) | TABLE_DUMP_V2::RIB_IPV6_MULTICAST(rib) => {
            print_rib(&rib, AFI::IPV6);
        }
        _ => {} // PEER_INDEX_TABLE, RIB_GENERIC, ADDPATH variants — skipped for brevity
    }
}

fn handle_v1(td: TABLE_DUMP) {
    // TABLE_DUMP attributes are a normal BGP attribute blob.
    // For IPv4 prefixes, the NEXT_HOP attribute is the canonical source.
    // For IPv6 prefixes, MP_REACH_NLRI carries the next hop.
    let nh = match td.prefix {
        IpAddr::V4(_) => find_next_hop_ipv4(&td.attributes),
        IpAddr::V6(_) => find_mp_reach_next_hop(&td.attributes),
    };
    println!(
        "{}/{} -> {}",
        td.prefix,
        td.prefix_length,
        nh.map(|ip| ip.to_string()).unwrap_or_else(|| "?".into()),
    );
}

fn print_rib(rib: &RIB_AFI, afi: AFI) {
    let prefix = bytes_to_ip(&rib.prefix, afi);
    for entry in &rib.entries {
        // In TABLE_DUMP_V2, IPv4 RIBs use the classic NEXT_HOP attribute,
        // IPv6 RIBs carry the next hop in MP_REACH_NLRI (compressed form).
        let nh = match afi {
            AFI::IPV4 => find_next_hop_ipv4(&entry.attributes),
            AFI::IPV6 => find_mp_reach_next_hop(&entry.attributes),
        };
        println!(
            "{}/{} -> {}",
            prefix,
            rib.prefix_length,
            nh.map(|ip| ip.to_string()).unwrap_or_else(|| "?".into()),
        );
    }
}

/// Reconstruct a full `IpAddr` from the variable-length prefix bytes that
/// MRT stores (only the significant bytes are present; the rest is implicitly zero).
fn bytes_to_ip(prefix: &[u8], afi: AFI) -> IpAddr {
    match afi {
        AFI::IPV4 => {
            let mut buf = [0u8; 4];
            buf[..prefix.len().min(4)].copy_from_slice(&prefix[..prefix.len().min(4)]);
            IpAddr::V4(Ipv4Addr::from(buf))
        }
        AFI::IPV6 => {
            let mut buf = [0u8; 16];
            buf[..prefix.len().min(16)].copy_from_slice(&prefix[..prefix.len().min(16)]);
            IpAddr::V6(Ipv6Addr::from(buf))
        }
    }
}

/// Iterate BGP path attributes (RFC 4271 §4.3) and invoke `f` for each.
///
/// Each attribute is: flags(1) + type(1) + length(1 or 2 if extended) + value.
fn for_each_attribute<F: FnMut(u8, &[u8])>(attrs: &[u8], mut f: F) {
    let mut i = 0;
    while i + 2 <= attrs.len() {
        let flags = attrs[i];
        let attr_type = attrs[i + 1];
        i += 2;

        let extended = (flags & 0x10) != 0;
        let (len, hdr) = if extended {
            if i + 2 > attrs.len() { return; }
            (u16::from_be_bytes([attrs[i], attrs[i + 1]]) as usize, 2)
        } else {
            if i + 1 > attrs.len() { return; }
            (attrs[i] as usize, 1)
        };
        i += hdr;

        if i + len > attrs.len() { return; }
        f(attr_type, &attrs[i..i + len]);
        i += len;
    }
}

const ATTR_NEXT_HOP: u8 = 3;
const ATTR_MP_REACH_NLRI: u8 = 14;

fn find_next_hop_ipv4(attrs: &[u8]) -> Option<IpAddr> {
    let mut out = None;
    for_each_attribute(attrs, |t, v| {
        if t == ATTR_NEXT_HOP && v.len() == 4 {
            out = Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3])));
        }
    });
    out
}

/// In TABLE_DUMP_V2 RIB entries, RFC 6396 §4.3.4 says MP_REACH_NLRI is encoded
/// with only `Next Hop Length (1) + Next Hop Address (N)` — the AFI/SAFI/NLRI
/// fields are omitted because they're already implied by the record subtype.
///
/// In regular BGP UPDATEs (and TABLE_DUMP v1), MP_REACH_NLRI uses the full
/// RFC 4760 layout. We try the compressed form first and fall back.
fn find_mp_reach_next_hop(attrs: &[u8]) -> Option<IpAddr> {
    let mut out = None;
    for_each_attribute(attrs, |t, v| {
        if t != ATTR_MP_REACH_NLRI || v.is_empty() {
            return;
        }
        // Compressed form (MRT TABLE_DUMP_V2 RIB entries).
        let nh_len = v[0] as usize;
        if 1 + nh_len <= v.len() {
            if let Some(ip) = parse_nexthop_bytes(&v[1..1 + nh_len]) {
                out = Some(ip);
                return;
            }
        }
        // Full RFC 4760 form: AFI(2) + SAFI(1) + nh_len(1) + nh + reserved(1) + NLRI...
        if v.len() >= 5 {
            let full_nh_len = v[3] as usize;
            if 4 + full_nh_len <= v.len() {
                if let Some(ip) = parse_nexthop_bytes(&v[4..4 + full_nh_len]) {
                    out = Some(ip);
                }
            }
        }
    });
    out
}

/// An IPv6 MP_REACH next hop is either 16 bytes (global) or 32 bytes
/// (global + link-local). We return the global address in the 32-byte case.
fn parse_nexthop_bytes(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Some(IpAddr::V4(Ipv4Addr::from(a)))
        }
        16 | 32 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[..16]);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}
