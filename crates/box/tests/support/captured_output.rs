use std::io::{Read, Result};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub struct CapturedOutput {
    reader: Option<JoinHandle<Result<Vec<u8>>>>,
    // DIAGNOSTIC (mcp-probe): bytes read so far, readable before EOF.
    seen: Arc<Mutex<Vec<u8>>>,
}

impl CapturedOutput {
    pub fn start(mut stream: impl Read + Send + 'static) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let reader = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&chunk[..read]);
            }
            Ok(sink.lock().unwrap().clone())
        });
        Self {
            reader: Some(reader),
            seen,
        }
    }

    /// DIAGNOSTIC (mcp-probe): what the stream has produced so far, without waiting for EOF.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<u8> {
        self.seen.lock().unwrap().clone()
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.reader
            .take()
            .expect("collect output once")
            .join()
            .expect("join the output reader")
            .expect("read process output")
    }
}
