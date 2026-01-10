//! Read-ahead I/O utilities for high-performance file parsing.
//!
//! This module provides a threaded read-ahead reader that can significantly
//! improve parsing throughput for large MRT files by overlapping I/O with parsing.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

/// A reader that performs read-ahead in a background thread.
///
/// This can significantly improve throughput when parsing large files by
/// overlapping disk I/O with CPU parsing work.
///
/// # Example
///
/// ```no_run
/// use std::io::BufReader;
/// use mrt_ingester::readahead::ReadAheadReader;
///
/// let reader = ReadAheadReader::open("large_file.mrt").unwrap();
/// let mut buffered = BufReader::new(reader);
///
/// while let Ok(Some((header, record))) = mrt_ingester::read(&mut buffered) {
///     // Process record
/// }
/// ```
pub struct ReadAheadReader {
    receiver: Receiver<Option<Vec<u8>>>,
    current_buf: Vec<u8>,
    pos: usize,
    _handle: JoinHandle<()>,
}

impl ReadAheadReader {
    /// Opens a file with read-ahead using default settings.
    ///
    /// Default: 4MB chunks, queue depth of 2.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Self::with_config(path, 4 * 1024 * 1024, 2)
    }

    /// Opens a file with custom read-ahead configuration.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to read
    /// * `chunk_size` - Size of each read chunk in bytes (recommended: 1-4 MB)
    /// * `queue_depth` - Number of chunks to buffer ahead (recommended: 2-4)
    pub fn with_config<P: AsRef<Path>>(
        path: P,
        chunk_size: usize,
        queue_depth: usize,
    ) -> std::io::Result<Self> {
        let file = File::open(path.as_ref())?;
        Ok(Self::from_file(file, chunk_size, queue_depth))
    }

    /// Creates a read-ahead reader from an already-opened file.
    pub fn from_file(mut file: File, chunk_size: usize, queue_depth: usize) -> Self {
        let (sender, receiver): (SyncSender<Option<Vec<u8>>>, _) =
            mpsc::sync_channel(queue_depth);

        let handle = thread::spawn(move || {
            loop {
                let mut buf = vec![0u8; chunk_size];
                match file.read(&mut buf) {
                    Ok(0) => {
                        // EOF
                        let _ = sender.send(None);
                        break;
                    }
                    Ok(n) => {
                        buf.truncate(n);
                        if sender.send(Some(buf)).is_err() {
                            // Receiver dropped
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
            _handle: handle,
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

/// Convenience function to create a high-performance reader for MRT files.
///
/// Returns a `BufReader` wrapping a `ReadAheadReader` with optimized settings.
///
/// # Example
///
/// ```no_run
/// let mut reader = mrt_ingester::readahead::open_mrt_file("large_file.mrt").unwrap();
///
/// while let Ok(Some((header, record))) = mrt_ingester::read(&mut reader) {
///     // Process record
/// }
/// ```
pub fn open_mrt_file<P: AsRef<Path>>(path: P) -> std::io::Result<BufReader<ReadAheadReader>> {
    let reader = ReadAheadReader::open(path)?;
    Ok(BufReader::with_capacity(64 * 1024, reader))
}
