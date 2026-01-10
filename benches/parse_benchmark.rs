//! Benchmarks for MRT parsing performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
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
            let _ = black_box(mrt_rs::read(&mut cursor));
        })
    });
}

fn benchmark_read_header_only(c: &mut Criterion) {
    // Multiple NULL records concatenated
    let mut data = Vec::new();
    for _ in 0..100 {
        data.extend_from_slice(&[
            0x5F, 0x5E, 0x10, 0x00, // timestamp
            0x00, 0x00, // type = 0 (NULL)
            0x00, 0x00, // subtype = 0
            0x00, 0x00, 0x00, 0x00, // length = 0
        ]);
    }

    c.bench_function("read_100_null_records", |b| {
        b.iter(|| {
            let mut cursor = Cursor::new(&data);
            let mut count = 0;
            while let Ok(Some(_)) = mrt_rs::read(&mut cursor) {
                count += 1;
            }
            black_box(count)
        })
    });
}

criterion_group!(benches, benchmark_read_null_record, benchmark_read_header_only);
criterion_main!(benches);
