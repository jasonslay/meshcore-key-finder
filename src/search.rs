use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::prefix::matches_prefix_hex;

pub const PROGRESS_BATCH: u64 = 1000;
pub const INTERRUPTED_EXIT_CODE: i32 = 130;

#[derive(Debug)]
pub struct SearchInterrupted {
    pub attempts: u64,
    pub elapsed: Duration,
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub signing_key: SigningKey,
    pub attempts: u64,
    pub elapsed: Duration,
}

pub fn resolve_worker_count(workers: Option<usize>) -> usize {
    workers.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
    })
}

pub fn format_with_commas(n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }

    let mut parts = Vec::new();
    let mut remaining = n;
    while remaining > 0 {
        parts.push(remaining % 1000);
        remaining /= 1000;
    }

    let mut formatted = parts.pop().unwrap().to_string();
    for part in parts.into_iter().rev() {
        formatted.push_str(&format!(",{part:03}"));
    }
    formatted
}

fn report_progress(attempts: u64, started: Instant, last_report: &mut Instant, workers: usize) {
    let now = Instant::now();
    if now.duration_since(*last_report) < Duration::from_secs(1) {
        return;
    }

    let elapsed = now.duration_since(started);
    let mut stderr = io::stderr();
    let _ = write!(
        stderr,
        "\rAttempts: {}  Rate: {}  Elapsed: {:.1}s",
        format_with_commas(attempts),
        format_rate(attempts, elapsed, workers),
        elapsed.as_secs_f64(),
    );
    let _ = stderr.flush();
    *last_report = now;
}

pub fn format_rate(attempts: u64, elapsed: Duration, workers: usize) -> String {
    if elapsed.is_zero() || attempts == 0 {
        return "0/s".to_string();
    }

    let seconds = elapsed.as_secs_f64();
    let total_rate = attempts as f64 / seconds;

    if workers <= 1 {
        return format!("{}/s", format_with_commas(total_rate.round() as u64));
    }

    let per_worker = total_rate / workers as f64;
    format!(
        "{}/s total (~{}/s per worker)",
        format_with_commas(total_rate.round() as u64),
        format_with_commas(per_worker.round() as u64),
    )
}

pub fn find_key_with_prefix(
    prefix: &str,
    avoid_reserved: bool,
    workers: usize,
    interrupted: Arc<AtomicBool>,
) -> Result<SearchResult, SearchInterrupted> {
    if workers <= 1 {
        return find_key_single(prefix, avoid_reserved, workers, interrupted);
    }
    find_key_parallel(prefix, avoid_reserved, workers, interrupted)
}

fn find_key_single(
    prefix: &str,
    avoid_reserved: bool,
    workers: usize,
    interrupted: Arc<AtomicBool>,
) -> Result<SearchResult, SearchInterrupted> {
    let started = Instant::now();
    let mut last_report = started;
    let mut attempts = 0u64;

    loop {
        if interrupted.load(Ordering::Relaxed) {
            return Err(SearchInterrupted {
                attempts,
                elapsed: started.elapsed(),
            });
        }

        attempts += 1;
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        if matches_prefix_hex(&public_key, prefix, avoid_reserved) {
            return Ok(SearchResult {
                signing_key,
                attempts,
                elapsed: started.elapsed(),
            });
        }

        report_progress(attempts, started, &mut last_report, workers);
    }
}

fn find_key_parallel(
    prefix: &str,
    avoid_reserved: bool,
    workers: usize,
    interrupted: Arc<AtomicBool>,
) -> Result<SearchResult, SearchInterrupted> {
    let started = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let attempt_counters: Arc<Vec<AtomicU64>> =
        Arc::new((0..workers).map(|_| AtomicU64::new(0)).collect());
    let (tx, rx) = mpsc::channel::<SigningKey>();

    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        let stop = Arc::clone(&stop);
        let interrupted = Arc::clone(&interrupted);
        let attempt_counters = Arc::clone(&attempt_counters);
        let tx = tx.clone();
        let prefix = prefix.to_string();

        handles.push(thread::spawn(move || {
            let mut local_attempts = 0u64;

            while !stop.load(Ordering::Relaxed) {
                if interrupted.load(Ordering::Relaxed) {
                    stop.store(true, Ordering::Relaxed);
                    break;
                }

                local_attempts += 1;
                if local_attempts.is_multiple_of(PROGRESS_BATCH) {
                    attempt_counters[worker_id].store(local_attempts, Ordering::Relaxed);
                }

                let signing_key = SigningKey::generate(&mut OsRng);
                let public_key = signing_key.verifying_key().to_bytes();

                if matches_prefix_hex(&public_key, &prefix, avoid_reserved) {
                    attempt_counters[worker_id].store(local_attempts, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    let _ = tx.send(signing_key);
                    return;
                }
            }

            attempt_counters[worker_id].store(local_attempts, Ordering::Relaxed);
        }));
    }

    drop(tx);

    let result = wait_for_match(rx, &attempt_counters, interrupted, &stop, started, workers);
    stop.store(true, Ordering::Relaxed);

    for handle in handles {
        let _ = handle.join();
    }

    result
}

fn total_attempts(counters: &[AtomicU64]) -> u64 {
    counters
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum()
}

fn wait_for_match(
    rx: Receiver<SigningKey>,
    attempt_counters: &[AtomicU64],
    interrupted: Arc<AtomicBool>,
    stop: &AtomicBool,
    started: Instant,
    workers: usize,
) -> Result<SearchResult, SearchInterrupted> {
    let mut last_report = started;

    loop {
        if interrupted.load(Ordering::Relaxed) {
            stop.store(true, Ordering::Relaxed);
            return Err(SearchInterrupted {
                attempts: total_attempts(attempt_counters),
                elapsed: started.elapsed(),
            });
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(signing_key) => {
                return Ok(SearchResult {
                    signing_key,
                    attempts: total_attempts(attempt_counters),
                    elapsed: started.elapsed(),
                });
            }
            Err(RecvTimeoutError::Timeout) => {
                report_progress(
                    total_attempts(attempt_counters),
                    started,
                    &mut last_report,
                    workers,
                );
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(SearchInterrupted {
                    attempts: total_attempts(attempt_counters),
                    elapsed: started.elapsed(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::public_key_hex;

    #[test]
    fn format_with_commas_formats_large_numbers() {
        assert_eq!(format_with_commas(0), "0");
        assert_eq!(format_with_commas(999), "999");
        assert_eq!(format_with_commas(1_000), "1,000");
        assert_eq!(format_with_commas(1_234_567), "1,234,567");
    }

    #[test]
    fn format_rate_single_worker() {
        let rate = format_rate(10_000, Duration::from_secs(2), 1);
        assert_eq!(rate, "5,000/s");
    }

    #[test]
    fn format_rate_multi_worker() {
        let rate = format_rate(80_000, Duration::from_secs(2), 4);
        assert_eq!(rate, "40,000/s total (~10,000/s per worker)");
    }

    #[test]
    fn find_key_single_char_prefix() {
        let interrupted = Arc::new(AtomicBool::new(false));
        let result = find_key_with_prefix("A", true, 1, Arc::clone(&interrupted)).unwrap();
        let public_hex = public_key_hex(&result.signing_key.verifying_key());
        assert!(public_hex.starts_with('A'));
        assert!(result.attempts >= 1);
    }

    #[test]
    fn find_key_parallel_two_workers() {
        let interrupted = Arc::new(AtomicBool::new(false));
        let result = find_key_with_prefix("A", true, 2, Arc::clone(&interrupted)).unwrap();
        let public_hex = public_key_hex(&result.signing_key.verifying_key());
        assert!(public_hex.starts_with('A'));
    }
}
