use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use meshcore_key_finder::{
    find_key_with_prefix, format_rate, format_with_commas, meshcore_private_key_hex,
    public_key_hex, resolve_worker_count, validate_prefix, SearchInterrupted,
    INTERRUPTED_EXIT_CODE,
};
use serde::Serialize;

#[derive(Parser)]
#[command(about = "Generate Ed25519 keys whose public key hex starts with a prefix.")]
struct Args {
    /// Hex prefix to match (1-64 characters).
    prefix: String,

    /// Number of worker threads (default: CPU count).
    #[arg(short = 'j', long)]
    workers: Option<usize>,

    /// Allow prefixes starting with 00 or FF (reserved in MeshCore).
    #[arg(long)]
    allow_reserved: bool,

    /// Print the result as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct JsonResult {
    public_key: String,
    private_key: String,
    prefix: String,
    attempts: u64,
    elapsed_seconds: f64,
    workers: usize,
    attempts_per_second: f64,
    attempts_per_second_per_worker: f64,
}

fn rate_stats(attempts: u64, elapsed: Duration, workers: usize) -> (f64, f64) {
    if elapsed.is_zero() {
        return (0.0, 0.0);
    }
    let total_rate = attempts as f64 / elapsed.as_secs_f64();
    (total_rate, total_rate / workers as f64)
}

fn main() {
    let args = Args::parse();
    let prefix = match validate_prefix(&args.prefix) {
        Ok(prefix) => prefix,
        Err(message) => {
            eprintln!("Error: {message}");
            std::process::exit(2);
        }
    };

    let worker_count = resolve_worker_count(args.workers);
    eprintln!(
        "Searching for public key prefix: {prefix} ({} worker{})",
        worker_count,
        if worker_count == 1 { "" } else { "s" }
    );

    let interrupted = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let interrupted = Arc::clone(&interrupted);
        move || {
            interrupted.store(true, Ordering::Relaxed);
        }
    })
    .expect("failed to set Ctrl+C handler");

    match find_key_with_prefix(&prefix, !args.allow_reserved, worker_count, interrupted) {
        Ok(result) => {
            let public_hex = public_key_hex(&result.signing_key.verifying_key());
            let private_hex = meshcore_private_key_hex(&result.signing_key);
            let elapsed = result.elapsed;
            let (attempts_per_second, attempts_per_second_per_worker) =
                rate_stats(result.attempts, elapsed, worker_count);

            eprintln!();
            eprintln!(
                "Found after {} attempts in {:.2}s ({})",
                format_with_commas(result.attempts),
                elapsed.as_secs_f64(),
                format_rate(result.attempts, elapsed, worker_count),
            );

            if args.json {
                let payload = JsonResult {
                    public_key: public_hex,
                    private_key: private_hex,
                    prefix: prefix.clone(),
                    attempts: result.attempts,
                    elapsed_seconds: (elapsed.as_secs_f64() * 1000.0).round() / 1000.0,
                    workers: worker_count,
                    attempts_per_second: (attempts_per_second * 1000.0).round() / 1000.0,
                    attempts_per_second_per_worker: (attempts_per_second_per_worker * 1000.0)
                        .round()
                        / 1000.0,
                };
                println!("{}", serde_json::to_string_pretty(&payload).unwrap());
            } else {
                println!("Public key:  {public_hex}");
                println!("Private key: {private_hex}");
            }
        }
        Err(SearchInterrupted { attempts, elapsed }) => {
            eprintln!();
            eprintln!(
                "Interrupted after {} attempts in {:.2}s ({})",
                format_with_commas(attempts),
                elapsed.as_secs_f64(),
                format_rate(attempts, elapsed, worker_count),
            );
            std::process::exit(INTERRUPTED_EXIT_CODE);
        }
    }
}
