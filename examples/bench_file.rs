// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmark parsing a real MRT file.
//!
//! Usage: cargo run --release --example bench_file <path_to_mrt_file>

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).map(|s| s.as_str()).unwrap_or("data.rib");

    let file = File::open(path).expect("Failed to open file");
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    drop(file);

    println!("File: {} ({:.2} MB)\n", path, file_size as f64 / 1_000_000.0);

    // Test standard BufReader
    {
        let file = File::open(path).expect("Failed to open file");
        let mut reader = BufReader::with_capacity(1024 * 1024, file);

        let start = Instant::now();
        let mut count = 0u64;

        while let Ok(Some((_header, _record))) = mrt_ingester::read(&mut reader) {
            count += 1;
        }

        let elapsed = start.elapsed();
        let mb_per_sec = (file_size as f64 / 1_000_000.0) / elapsed.as_secs_f64();

        println!("BufReader (1MB):    {} records in {:.3}s = {:.2} MB/sec",
            count, elapsed.as_secs_f64(), mb_per_sec);
    }

    // Test read-ahead reader
    {
        let mut reader = mrt_ingester::readahead::open_mrt_file(path).expect("Failed to open file");

        let start = Instant::now();
        let mut count = 0u64;

        while let Ok(Some((_header, _record))) = mrt_ingester::read(&mut reader) {
            count += 1;
        }

        let elapsed = start.elapsed();
        let mb_per_sec = (file_size as f64 / 1_000_000.0) / elapsed.as_secs_f64();

        println!("ReadAhead (4MB/2):  {} records in {:.3}s = {:.2} MB/sec",
            count, elapsed.as_secs_f64(), mb_per_sec);
    }
}
