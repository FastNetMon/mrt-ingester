//! Benchmark different read-ahead strategies for MRT file parsing.
//!
//! Tests: BufReader sizes, mmap, and threaded read-ahead.

use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

fn bench_bufreader(path: &str, buf_size: usize) -> (u64, f64) {
    let file = File::open(path).expect("Failed to open file");
    let mut reader = BufReader::with_capacity(buf_size, file);

    let start = Instant::now();
    let mut count = 0u64;

    while let Ok(Some((_header, _record))) = mrt_ingester::read(&mut reader) {
        count += 1;
    }

    (count, start.elapsed().as_secs_f64())
}

fn bench_mmap(path: &str) -> (u64, f64) {
    use std::io::Cursor;

    let file = File::open(path).expect("Failed to open file");
    let mmap = unsafe { memmap2::Mmap::map(&file).expect("Failed to mmap") };
    let mut cursor = Cursor::new(&mmap[..]);

    let start = Instant::now();
    let mut count = 0u64;

    while let Ok(Some((_header, _record))) = mrt_ingester::read(&mut cursor) {
        count += 1;
    }

    (count, start.elapsed().as_secs_f64())
}

/// Double-buffered reader that reads ahead in a separate thread
struct ReadAheadReader {
    receiver: mpsc::Receiver<Option<Vec<u8>>>,
    current_buf: Vec<u8>,
    pos: usize,
}

impl ReadAheadReader {
    fn new(path: String, chunk_size: usize, queue_depth: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel(queue_depth);

        thread::spawn(move || {
            let mut file = File::open(&path).expect("Failed to open file");
            loop {
                let mut buf = vec![0u8; chunk_size];
                match file.read(&mut buf) {
                    Ok(0) => {
                        let _ = sender.send(None); // EOF
                        break;
                    }
                    Ok(n) => {
                        buf.truncate(n);
                        if sender.send(Some(buf)).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = sender.send(None);
                        break;
                    }
                }
            }
        });

        ReadAheadReader {
            receiver,
            current_buf: Vec::new(),
            pos: 0,
        }
    }

    fn fill_buffer(&mut self) -> bool {
        if self.pos < self.current_buf.len() {
            return true;
        }
        match self.receiver.recv() {
            Ok(Some(buf)) => {
                self.current_buf = buf;
                self.pos = 0;
                true
            }
            _ => false,
        }
    }
}

impl Read for ReadAheadReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.fill_buffer() {
            return Ok(0);
        }

        let available = self.current_buf.len() - self.pos;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&self.current_buf[self.pos..self.pos + to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }
}

fn bench_readahead(path: &str, chunk_size: usize, queue_depth: usize) -> (u64, f64) {
    let reader = ReadAheadReader::new(path.to_string(), chunk_size, queue_depth);
    let mut reader = BufReader::with_capacity(64 * 1024, reader);

    let start = Instant::now();
    let mut count = 0u64;

    while let Ok(Some((_header, _record))) = mrt_ingester::read(&mut reader) {
        count += 1;
    }

    (count, start.elapsed().as_secs_f64())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).map(|s| s.as_str()).unwrap_or("data.rib");

    let file = File::open(path).expect("Failed to open file");
    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
    drop(file);

    println!("File: {} ({:.2} MB)\n", path, file_size as f64 / 1_000_000.0);
    println!("{:<40} {:>12} {:>12} {:>12}", "Strategy", "Records", "Time (s)", "MB/sec");
    println!("{}", "-".repeat(80));

    // Test different BufReader sizes
    for &buf_size in &[64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let (count, time) = bench_bufreader(path, buf_size);
        let mb_sec = (file_size as f64 / 1_000_000.0) / time;
        println!("BufReader {:>6} KB                       {:>12} {:>12.3} {:>12.2}",
            buf_size / 1024, count, time, mb_sec);
    }

    println!();

    // Test mmap
    let (count, time) = bench_mmap(path);
    let mb_sec = (file_size as f64 / 1_000_000.0) / time;
    println!("{:<40} {:>12} {:>12.3} {:>12.2}", "Memory-mapped (mmap)", count, time, mb_sec);

    println!();

    // Test threaded read-ahead with different configurations
    for &(chunk, depth) in &[(1024 * 1024, 4), (4 * 1024 * 1024, 2), (4 * 1024 * 1024, 8)] {
        let (count, time) = bench_readahead(path, chunk, depth);
        let mb_sec = (file_size as f64 / 1_000_000.0) / time;
        println!("ReadAhead chunk={:>4}MB depth={:<2}            {:>12} {:>12.3} {:>12.2}",
            chunk / (1024 * 1024), depth, count, time, mb_sec);
    }
}
