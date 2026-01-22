// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmarks for MRT parsing performance.
//!
//! Run with: cargo bench
//! Run with profiling: cargo bench --bench parse_benchmark -- --profile-time=5

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use pprof::criterion::{Output, PProfProfiler};
use std::io::Cursor;

fn benchmark_read_null_record(c: &mut Criterion) {
    let data: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x01, // timestamp = 1
        0x00, 0x00, // type = 0 (NULL)
        0x00, 0x00, // subtype = 0
        0x00, 0x00, 0x00, 0x00, // length = 0
    ];

    c.bench_function("read_null_record", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(&data);
            let _ = black_box(mrt_ingester::read(&mut cursor));
        })
    });
}

fn benchmark_read_with_buffer_reuse(c: &mut Criterion) {
    // Multiple NULL records concatenated
    let mut data = Vec::new();
    for _ in 0..1000 {
        data.extend_from_slice(&[
            0x5F, 0x5E, 0x10, 0x00, // timestamp
            0x00, 0x00, // type = 0 (NULL)
            0x00, 0x00, // subtype = 0
            0x00, 0x00, 0x00, 0x00, // length = 0
        ]);
    }

    let mut group = c.benchmark_group("buffer_reuse");

    // Without buffer reuse (standard read)
    group.bench_function("read_1000_without_reuse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(&data);
            let mut count = 0;
            while let Ok(Some(_)) = mrt_ingester::read(&mut cursor) {
                count += 1;
            }
            black_box(count)
        })
    });

    // With buffer reuse
    group.bench_function("read_1000_with_reuse", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(&data);
            let mut body_buf = Vec::with_capacity(4096);
            let mut count = 0;
            while let Ok(Some(_)) = mrt_ingester::read_with_buffer(&mut cursor, &mut body_buf) {
                count += 1;
            }
            black_box(count)
        })
    });

    group.finish();
}

fn benchmark_bgp4mp_messages(c: &mut Criterion) {
    // Simulate BGP4MP MESSAGE_AS4 records with varying message sizes
    fn create_bgp4mp_record(message_size: usize) -> Vec<u8> {
        let body_len = 20 + message_size; // 4+4+2+2+4+4 = 20 for IPv4
        let mut record = Vec::new();
        record.extend_from_slice(&[0x5F, 0x5E, 0x10, 0x00]); // timestamp
        record.extend_from_slice(&[0x00, 0x10]); // type = 16 (BGP4MP)
        record.extend_from_slice(&[0x00, 0x04]); // subtype = 4 (MESSAGE_AS4)
        record.extend_from_slice(&(body_len as u32).to_be_bytes()); // length
        // Body
        record.extend_from_slice(&[0x00, 0x00, 0xFD, 0xE8]); // peer_as
        record.extend_from_slice(&[0x00, 0x00, 0xFD, 0xE9]); // local_as
        record.extend_from_slice(&[0x00, 0x00]); // interface
        record.extend_from_slice(&[0x00, 0x01]); // AFI = IPv4
        record.extend_from_slice(&[192, 168, 1, 1]); // peer_address
        record.extend_from_slice(&[10, 0, 0, 1]); // local_address
        record.extend_from_slice(&vec![0u8; message_size]); // message
        record
    }

    let mut group = c.benchmark_group("bgp4mp_message_sizes");

    for size in [64, 256, 1024, 4096].iter() {
        let record = create_bgp4mp_record(*size);

        group.bench_with_input(BenchmarkId::new("with_reuse", size), size, |b, _| {
            b.iter(|| {
                let mut cursor = Cursor::new(&record);
                let mut body_buf = Vec::with_capacity(8192);
                let _ = black_box(mrt_ingester::read_with_buffer(&mut cursor, &mut body_buf));
            })
        });

        group.bench_with_input(BenchmarkId::new("without_reuse", size), size, |b, _| {
            b.iter(|| {
                let mut cursor = Cursor::new(&record);
                let _ = black_box(mrt_ingester::read(&mut cursor));
            })
        });
    }

    group.finish();
}

fn benchmark_table_dump_v2(c: &mut Criterion) {
    // Create a RIB_IPV4_UNICAST record with multiple entries
    fn create_rib_record(entry_count: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // sequence_number
        body.push(24); // prefix_length = /24
        body.extend_from_slice(&[192, 168, 1]); // prefix (3 bytes)
        body.extend_from_slice(&entry_count.to_be_bytes()); // entry_count

        for i in 0..entry_count {
            body.extend_from_slice(&(i as u16).to_be_bytes()); // peer_index
            body.extend_from_slice(&[0x5F, 0x5E, 0x10, 0x00]); // originated_time
            body.extend_from_slice(&[0x00, 0x10]); // attr_len = 16
            body.extend_from_slice(&[0u8; 16]); // attributes
        }

        let body_len = body.len() as u32;
        let mut record = Vec::new();
        record.extend_from_slice(&[0x5F, 0x5E, 0x10, 0x00]); // timestamp
        record.extend_from_slice(&[0x00, 0x0D]); // type = 13 (TABLE_DUMP_V2)
        record.extend_from_slice(&[0x00, 0x02]); // subtype = 2 (RIB_IPV4_UNICAST)
        record.extend_from_slice(&body_len.to_be_bytes()); // length
        record.extend_from_slice(&body);
        record
    }

    let mut group = c.benchmark_group("table_dump_v2");

    for count in [1, 10, 50, 100].iter() {
        let record = create_rib_record(*count);

        group.bench_with_input(BenchmarkId::new("entries", count), count, |b, _| {
            b.iter(|| {
                let mut cursor = Cursor::new(&record);
                let mut body_buf = Vec::with_capacity(8192);
                let _ = black_box(mrt_ingester::read_with_buffer(&mut cursor, &mut body_buf));
            })
        });
    }

    group.finish();
}

// Standard criterion group (no profiling)
criterion_group!(
    benches,
    benchmark_read_null_record,
    benchmark_read_with_buffer_reuse,
    benchmark_bgp4mp_messages,
    benchmark_table_dump_v2,
);

// Profiled criterion group - generates flamegraphs
criterion_group!(
    name = profiled;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = benchmark_read_with_buffer_reuse, benchmark_bgp4mp_messages, benchmark_table_dump_v2
);

// Use 'benches' for normal runs, 'profiled' for flamegraph generation
criterion_main!(benches);

// To run with profiling, change the line above to:
// criterion_main!(profiled);
// Then run: cargo bench --bench parse_benchmark
// Flamegraphs will be in target/criterion/*/profile/flamegraph.svg
