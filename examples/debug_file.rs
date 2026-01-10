//! Debug MRT file parsing.

use std::env;
use std::fs::File;
use std::io::BufReader;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).map(|s| s.as_str()).unwrap_or("data.rib");

    println!("Opening file: {}", path);
    let file = File::open(path).expect("Failed to open file");
    let mut reader = BufReader::with_capacity(1024 * 1024, file);

    for i in 0..5 {
        match mrt_ingester::read(&mut reader) {
            Ok(Some((header, _record))) => {
                println!("Record {}: type={}, subtype={}, length={}",
                    i, header.record_type, header.sub_type, header.length);
            }
            Ok(None) => {
                println!("Record {}: EOF", i);
                break;
            }
            Err(e) => {
                println!("Record {}: Error: {:?}", i, e);
                break;
            }
        }
    }
}
