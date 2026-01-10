//! Profile MRT file parsing to identify bottlenecks.

use std::env;
use std::fs::File;
use std::io::BufReader;
use std::time::Instant;
use std::collections::HashMap;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).map(|s| s.as_str()).unwrap_or("data.rib");

    println!("Profiling file: {}", path);
    let file = File::open(path).expect("Failed to open file");
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);

    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut body_buf = Vec::with_capacity(65536);

    let mut record_counts: HashMap<u16, u64> = HashMap::new();
    let mut total_body_bytes = 0u64;

    let start = Instant::now();
    while let Ok(Some((header, _record))) = mrt_ingester::read_with_buffer(&mut reader, &mut body_buf) {
        *record_counts.entry(header.record_type).or_insert(0) += 1;
        total_body_bytes += header.length as u64;
    }
    let elapsed = start.elapsed();

    println!("\nFile size: {:.2} MB", file_size as f64 / 1_000_000.0);
    println!("Total body bytes: {:.2} MB", total_body_bytes as f64 / 1_000_000.0);
    println!("Time: {:.3} seconds", elapsed.as_secs_f64());
    println!("Throughput: {:.2} MB/sec", (file_size as f64 / 1_000_000.0) / elapsed.as_secs_f64());

    println!("\nRecord type distribution:");
    let mut counts: Vec<_> = record_counts.into_iter().collect();
    counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    for (record_type, count) in counts {
        let name = match record_type {
            0 => "NULL",
            12 => "TABLE_DUMP",
            13 => "TABLE_DUMP_V2",
            16 => "BGP4MP",
            17 => "BGP4MP_ET",
            _ => "OTHER",
        };
        println!("  Type {:2} ({:12}): {:>10} records", record_type, name, count);
    }
}
