// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sanity check: all read paths must agree on record/entry/attribute counts.
//!
//! Usage: cargo run --release --example compare_paths <path_to_mrt_file>

use std::io::{Cursor, Read};

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../mrt/data.rib.gz".to_string());
    let mut data = Vec::new();
    mrt_ingester::open(&path)
        .expect("Failed to open file")
        .take(64 * 1024 * 1024)
        .read_to_end(&mut data)
        .expect("Failed to read file");

    // Owned path
    let mut cursor = Cursor::new(&data);
    let mut owned_records = 0u64;
    let mut owned_entries = 0u64;
    let mut owned_attr_bytes = 0u64;
    while let Ok(Some((_h, record))) = mrt_ingester::read(&mut cursor) {
        owned_records += 1;
        if let mrt_ingester::Record::TABLE_DUMP_V2(td) = &record {
            use mrt_ingester::tabledump::TABLE_DUMP_V2::*;
            let rib = match td {
                RIB_IPV4_UNICAST(r) | RIB_IPV4_MULTICAST(r) | RIB_IPV6_UNICAST(r)
                | RIB_IPV6_MULTICAST(r) => Some(r),
                _ => None,
            };
            if let Some(r) = rib {
                owned_entries += r.entries.len() as u64;
                owned_attr_bytes += r.entries.iter().map(|e| e.attributes.len() as u64).sum::<u64>();
            }
        }
    }

    // Zero-copy stream path
    let mut cursor = Cursor::new(&data);
    let mut body_buf = Vec::with_capacity(64 * 1024);
    let mut zc_records = 0u64;
    let mut zc_entries = 0u64;
    let mut zc_attr_bytes = 0u64;
    while let Ok(Some((_h, record))) = mrt_ingester::read_ref(&mut cursor, &mut body_buf) {
        zc_records += 1;
        if let mrt_ingester::RecordRef::RIB(rib) = record {
            for entry in rib.entries() {
                let entry = entry.expect("entry parse error");
                zc_entries += 1;
                zc_attr_bytes += entry.attributes.len() as u64;
            }
        }
    }

    // Slice path
    let mut pos = 0usize;
    let mut sl_records = 0u64;
    let mut sl_entries = 0u64;
    let mut sl_attr_bytes = 0u64;
    while let Ok(Some((_h, record))) = mrt_ingester::read_ref_from_slice(&data, &mut pos) {
        sl_records += 1;
        if let mrt_ingester::RecordRef::RIB(rib) = record {
            for entry in rib.entries() {
                let entry = entry.expect("entry parse error");
                sl_entries += 1;
                sl_attr_bytes += entry.attributes.len() as u64;
            }
        }
    }

    println!("owned:     {owned_records} records, {owned_entries} entries, {owned_attr_bytes} attr bytes");
    println!("zero_copy: {zc_records} records, {zc_entries} entries, {zc_attr_bytes} attr bytes");
    println!("slice:     {sl_records} records, {sl_entries} entries, {sl_attr_bytes} attr bytes");

    assert_eq!(owned_records, zc_records);
    assert_eq!(zc_records, sl_records);
    assert_eq!(zc_entries, sl_entries);
    assert_eq!(zc_attr_bytes, sl_attr_bytes);
    println!("OK: all paths agree");
}
