use clap::Parser;
use hdrhistogram::Histogram;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::sync::Semaphore;

#[derive(Parser, Debug)]
#[command(name = "ngx-l402-stress-test", about = "Stress test for ngx_l402 module")]
struct Args {
    /// Target URL to test (e.g., http://localhost:8000/protected)
    #[arg(short, long)]
    url: String,

    /// Number of concurrent connections
    #[arg(short, long, default_value = "50")]
    concurrency: usize,

    /// Total number of requests to send
    #[arg(short = 'n', long, default_value = "10000")]
    requests: usize,

    /// Warmup period in seconds (results discarded)
    #[arg(short, long, default_value = "3")]
    warmup_secs: u64,

    /// Optional Authorization header value (e.g., "L402 macaroon:preimage" or "Cashu token...")
    #[arg(short, long)]
    auth: Option<String>,

    /// Save results to JSON file for later comparison
    #[arg(short, long)]
    save: Option<String>,

    /// Compare against a previous baseline JSON file
    #[arg(long)]
    compare: Option<String>,

    /// Run concurrency sweep (1, 10, 25, 50, 100)
    #[arg(long)]
    sweep: bool,

    /// NGINX process name to monitor for RSS (default: "nginx")
    #[arg(long, default_value = "nginx")]
    process_name: String,

    /// Memory sampling interval in milliseconds
    #[arg(long, default_value = "1000")]
    memory_interval_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct BenchmarkResult {
    url: String,
    concurrency: usize,
    total_requests: usize,
    warmup_secs: u64,
    duration_secs: f64,
    throughput_rps: f64,
    latency_p50_us: u64,
    latency_p90_us: u64,
    latency_p95_us: u64,
    latency_p99_us: u64,
    latency_max_us: u64,
    latency_mean_us: f64,
    error_count: usize,
    status_codes: std::collections::HashMap<u16, usize>,
    memory: MemoryResult,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct MemoryResult {
    initial_rss_kb: u64,
    peak_rss_kb: u64,
    final_rss_kb: u64,
    rss_growth_kb: i64,
    samples: Vec<MemorySample>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct MemorySample {
    elapsed_secs: f64,
    rss_kb: u64,
}

/// Collect RSS of all matching processes (sum of all workers)
fn collect_rss(sys: &mut System, process_name: &str) -> u64 {
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    let mut total_rss_kb = 0u64;
    for (_pid, process) in sys.processes() {
        if process.name().to_string_lossy().contains(process_name) {
            total_rss_kb += process.memory() / 1024; // bytes to KB
        }
    }
    total_rss_kb
}

async fn run_benchmark(
    url: &str,
    concurrency: usize,
    total_requests: usize,
    warmup_secs: u64,
    auth: Option<&str>,
    process_name: &str,
    memory_interval_ms: u64,
) -> BenchmarkResult {
    let client = Client::builder()
        .pool_max_idle_per_host(concurrency)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client");

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let success_count = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));
    let warmup_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Status code tracking
    let status_200 = Arc::new(AtomicUsize::new(0));
    let status_401 = Arc::new(AtomicUsize::new(0));
    let status_402 = Arc::new(AtomicUsize::new(0));
    let status_500 = Arc::new(AtomicUsize::new(0));
    let status_other = Arc::new(AtomicUsize::new(0));

    // Latency tracking - use atomic u64 array approach for thread safety
    // We'll collect latencies in a channel
    let (latency_tx, mut latency_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();

    // Memory tracking
    let memory_samples = Arc::new(tokio::sync::Mutex::new(Vec::<MemorySample>::new()));
    let peak_rss = Arc::new(AtomicU64::new(0));
    let initial_rss = Arc::new(AtomicU64::new(0));
    let memory_running = Arc::new(std::sync::atomic::AtomicBool::new(true));

    // Start memory monitoring task
    let mem_samples_clone = memory_samples.clone();
    let peak_rss_clone = peak_rss.clone();
    let initial_rss_clone = initial_rss.clone();
    let memory_running_clone = memory_running.clone();
    let proc_name = process_name.to_string();
    let mem_task = tokio::spawn(async move {
        let mut sys = System::new();
        let start = Instant::now();

        // Collect initial RSS
        let init_rss = collect_rss(&mut sys, &proc_name);
        initial_rss_clone.store(init_rss, Ordering::Relaxed);

        loop {
            if !memory_running_clone.load(Ordering::Relaxed) {
                break;
            }

            let rss = collect_rss(&mut sys, &proc_name);
            let elapsed = start.elapsed().as_secs_f64();

            // Update peak
            let current_peak = peak_rss_clone.load(Ordering::Relaxed);
            if rss > current_peak {
                peak_rss_clone.store(rss, Ordering::Relaxed);
            }

            let mut samples = mem_samples_clone.lock().await;
            samples.push(MemorySample {
                elapsed_secs: elapsed,
                rss_kb: rss,
            });

            tokio::time::sleep(Duration::from_millis(memory_interval_ms)).await;
        }
    });

    // Warmup phase
    println!(
        "  Warming up for {}s ({} concurrent)...",
        warmup_secs, concurrency
    );
    let warmup_start = Instant::now();
    let mut warmup_handles = Vec::new();

    while warmup_start.elapsed() < Duration::from_secs(warmup_secs) {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.to_string();
        let auth = auth.map(|s| s.to_string());

        let handle = tokio::spawn(async move {
            let mut req = client.get(&url);
            if let Some(ref auth_val) = auth {
                req = req.header("Authorization", auth_val.as_str());
            }
            let _ = req.send().await;
            drop(permit);
        });
        warmup_handles.push(handle);
    }

    // Wait for warmup to complete
    for h in warmup_handles {
        let _ = h.await;
    }
    warmup_done.store(true, Ordering::Release);
    println!("  Warmup complete. Starting measured run...");

    // Measured phase
    let bench_start = Instant::now();
    let mut handles = Vec::with_capacity(total_requests);

    for i in 0..total_requests {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let url = url.to_string();
        let auth = auth.map(|s| s.to_string());
        let success_count = success_count.clone();
        let error_count = error_count.clone();
        let s200 = status_200.clone();
        let s401 = status_401.clone();
        let s402 = status_402.clone();
        let s500 = status_500.clone();
        let s_other = status_other.clone();
        let latency_tx = latency_tx.clone();

        let handle = tokio::spawn(async move {
            let start = Instant::now();

            let mut req = client.get(&url);
            if let Some(ref auth_val) = auth {
                req = req.header("Authorization", auth_val.as_str());
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    match status {
                        200 | 204 => {
                            s200.fetch_add(1, Ordering::Relaxed);
                        }
                        401 => {
                            s401.fetch_add(1, Ordering::Relaxed);
                        }
                        402 => {
                            s402.fetch_add(1, Ordering::Relaxed);
                        }
                        500..=599 => {
                            s500.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            s_other.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    error_count.fetch_add(1, Ordering::Relaxed);
                }
            }

            let elapsed_us = start.elapsed().as_micros() as u64;
            let _ = latency_tx.send(elapsed_us);
            drop(permit);
        });
        handles.push(handle);

        // Progress reporting
        if (i + 1) % 1000 == 0 {
            print!("\r  Progress: {}/{}", i + 1, total_requests);
        }
    }

    // Wait for all requests
    for h in handles {
        let _ = h.await;
    }
    let bench_duration = bench_start.elapsed();
    println!("\r  Progress: {}/{}  ", total_requests, total_requests);

    // Stop memory monitoring
    memory_running.store(false, Ordering::Relaxed);
    let _ = mem_task.await;

    // Drop sender and collect latencies into histogram
    drop(latency_tx);
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap(); // 1us to 60s
    while let Some(latency_us) = latency_rx.recv().await {
        let _ = histogram.record(latency_us);
    }

    // Collect final RSS
    let mut sys = System::new();
    let final_rss = collect_rss(&mut sys, process_name);

    // Build status codes map
    let mut status_codes = std::collections::HashMap::new();
    let s200_val = status_200.load(Ordering::Relaxed);
    let s401_val = status_401.load(Ordering::Relaxed);
    let s402_val = status_402.load(Ordering::Relaxed);
    let s500_val = status_500.load(Ordering::Relaxed);
    let s_other_val = status_other.load(Ordering::Relaxed);
    if s200_val > 0 {
        status_codes.insert(200, s200_val);
    }
    if s401_val > 0 {
        status_codes.insert(401, s401_val);
    }
    if s402_val > 0 {
        status_codes.insert(402, s402_val);
    }
    if s500_val > 0 {
        status_codes.insert(500, s500_val);
    }
    if s_other_val > 0 {
        status_codes.insert(0, s_other_val);
    }

    let memory_samples_vec = memory_samples.lock().await.clone();
    let init_rss = initial_rss.load(Ordering::Relaxed);
    let peak = peak_rss.load(Ordering::Relaxed);

    BenchmarkResult {
        url: url.to_string(),
        concurrency,
        total_requests,
        warmup_secs,
        duration_secs: bench_duration.as_secs_f64(),
        throughput_rps: total_requests as f64 / bench_duration.as_secs_f64(),
        latency_p50_us: histogram.value_at_quantile(0.50),
        latency_p90_us: histogram.value_at_quantile(0.90),
        latency_p95_us: histogram.value_at_quantile(0.95),
        latency_p99_us: histogram.value_at_quantile(0.99),
        latency_max_us: histogram.max(),
        latency_mean_us: histogram.mean(),
        error_count: error_count.load(Ordering::Relaxed),
        status_codes,
        memory: MemoryResult {
            initial_rss_kb: init_rss,
            peak_rss_kb: peak,
            final_rss_kb: final_rss,
            rss_growth_kb: final_rss as i64 - init_rss as i64,
            samples: memory_samples_vec,
        },
    }
}

fn print_result(result: &BenchmarkResult) {
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║            STRESS TEST RESULTS                  ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║ URL:          {:<35}║", result.url);
    println!("║ Concurrency:  {:<35}║", result.concurrency);
    println!("║ Requests:     {:<35}║", result.total_requests);
    println!("║ Duration:     {:<35}║", format!("{:.2}s", result.duration_secs));
    println!("║ Throughput:   {:<35}║", format!("{:.1} req/s", result.throughput_rps));
    println!("╠══════════════════════════════════════════════════╣");
    println!("║ LATENCY                                         ║");
    println!("║   p50:  {:<41}║", format_latency(result.latency_p50_us));
    println!("║   p90:  {:<41}║", format_latency(result.latency_p90_us));
    println!("║   p95:  {:<41}║", format_latency(result.latency_p95_us));
    println!("║   p99:  {:<41}║", format_latency(result.latency_p99_us));
    println!("║   max:  {:<41}║", format_latency(result.latency_max_us));
    println!("║   mean: {:<41}║", format_latency(result.latency_mean_us as u64));
    println!("╠══════════════════════════════════════════════════╣");
    println!("║ STATUS CODES                                    ║");
    for (code, count) in &result.status_codes {
        println!("║   {}: {:<42}║", code, count);
    }
    println!("║ Errors: {:<41}║", result.error_count);
    println!("╠══════════════════════════════════════════════════╣");
    println!("║ MEMORY (NGINX workers RSS)                      ║");
    println!("║   Initial: {:<38}║", format!("{} KB", result.memory.initial_rss_kb));
    println!("║   Peak:    {:<38}║", format!("{} KB", result.memory.peak_rss_kb));
    println!("║   Final:   {:<38}║", format!("{} KB", result.memory.final_rss_kb));
    println!("║   Growth:  {:<38}║", format!("{:+} KB", result.memory.rss_growth_kb));
    println!("╚══════════════════════════════════════════════════╝");
}

fn format_latency(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{}us", us)
    }
}

fn print_comparison(baseline: &BenchmarkResult, current: &BenchmarkResult) {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    COMPARISON (baseline vs current)             ║");
    println!("╠═══════════════════╦══════════════╦══════════════╦═══════════════╣");
    println!("║ Metric            ║ Baseline     ║ Current      ║ Delta         ║");
    println!("╠═══════════════════╬══════════════╬══════════════╬═══════════════╣");

    print_comparison_row(
        "Throughput (rps)",
        baseline.throughput_rps,
        current.throughput_rps,
        true,
    );
    print_comparison_row_us("Latency p50", baseline.latency_p50_us, current.latency_p50_us);
    print_comparison_row_us("Latency p90", baseline.latency_p90_us, current.latency_p90_us);
    print_comparison_row_us("Latency p95", baseline.latency_p95_us, current.latency_p95_us);
    print_comparison_row_us("Latency p99", baseline.latency_p99_us, current.latency_p99_us);
    print_comparison_row_us("Latency max", baseline.latency_max_us, current.latency_max_us);
    print_comparison_row(
        "Errors",
        baseline.error_count as f64,
        current.error_count as f64,
        false,
    );

    println!("╠═══════════════════╬══════════════╬══════════════╬═══════════════╣");
    println!("║ MEMORY            ║              ║              ║               ║");
    print_comparison_row(
        "  Peak RSS (KB)",
        baseline.memory.peak_rss_kb as f64,
        current.memory.peak_rss_kb as f64,
        false,
    );
    print_comparison_row(
        "  RSS Growth (KB)",
        baseline.memory.rss_growth_kb as f64,
        current.memory.rss_growth_kb as f64,
        false,
    );
    println!("╚═══════════════════╩══════════════╩══════════════╩═══════════════╝");
}

fn print_comparison_row(label: &str, baseline: f64, current: f64, higher_is_better: bool) {
    let delta = current - baseline;
    let pct = if baseline != 0.0 {
        (delta / baseline) * 100.0
    } else {
        0.0
    };

    let delta_str = if (higher_is_better && delta > 0.0) || (!higher_is_better && delta < 0.0) {
        format!("{:+.1} ({:+.1}%)", delta, pct)
    } else if delta == 0.0 {
        "  0 (0.0%)".to_string()
    } else {
        format!("{:+.1} ({:+.1}%)", delta, pct)
    };

    println!(
        "║ {:<17} ║ {:<12.1} ║ {:<12.1} ║ {:<13} ║",
        label, baseline, current, delta_str
    );
}

fn print_comparison_row_us(label: &str, baseline_us: u64, current_us: u64) {
    let delta = current_us as i64 - baseline_us as i64;
    let pct = if baseline_us != 0 {
        (delta as f64 / baseline_us as f64) * 100.0
    } else {
        0.0
    };

    let delta_str = format!("{:+} ({:+.1}%)", delta, pct);
    println!(
        "║ {:<17} ║ {:<12} ║ {:<12} ║ {:<13} ║",
        label,
        format_latency(baseline_us),
        format_latency(current_us),
        delta_str,
    );
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("ngx_l402 Stress Test");
    println!("====================");

    if args.sweep {
        // Concurrency sweep mode
        let levels = vec![1, 10, 25, 50, 100];
        let mut results = Vec::new();

        for &c in &levels {
            println!("\n--- Concurrency: {} ---", c);
            let result = run_benchmark(
                &args.url,
                c,
                args.requests,
                args.warmup_secs,
                args.auth.as_deref(),
                &args.process_name,
                args.memory_interval_ms,
            )
            .await;
            print_result(&result);
            results.push(result);
        }

        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║              CONCURRENCY SWEEP SUMMARY                  ║");
        println!("╠═════════════╦══════════╦══════════╦══════════╦══════════╣");
        println!("║ Concurrency ║ RPS      ║ p50      ║ p99      ║ Peak RSS ║");
        println!("╠═════════════╬══════════╬══════════╬══════════╬══════════╣");
        for r in &results {
            println!(
                "║ {:<11} ║ {:<8.0} ║ {:<8} ║ {:<8} ║ {:<8} ║",
                r.concurrency,
                r.throughput_rps,
                format_latency(r.latency_p50_us),
                format_latency(r.latency_p99_us),
                format!("{}KB", r.memory.peak_rss_kb),
            );
        }
        println!("╚═════════════╩══════════╩══════════╩══════════╩══════════╝");

        if let Some(ref path) = args.save {
            let json = serde_json::to_string_pretty(&results).unwrap();
            std::fs::write(path, json).unwrap();
            println!("\nSweep results saved to: {}", path);
        }
    } else {
        // Single benchmark run
        println!(
            "\nTarget: {} | Concurrency: {} | Requests: {}",
            args.url, args.concurrency, args.requests
        );

        let result = run_benchmark(
            &args.url,
            args.concurrency,
            args.requests,
            args.warmup_secs,
            args.auth.as_deref(),
            &args.process_name,
            args.memory_interval_ms,
        )
        .await;

        print_result(&result);

        // Save results
        if let Some(ref path) = args.save {
            let json = serde_json::to_string_pretty(&result).unwrap();
            std::fs::write(path, json).unwrap();
            println!("\nResults saved to: {}", path);
        }

        // Compare with baseline
        if let Some(ref baseline_path) = args.compare {
            match std::fs::read_to_string(baseline_path) {
                Ok(json) => match serde_json::from_str::<BenchmarkResult>(&json) {
                    Ok(baseline) => {
                        print_comparison(&baseline, &result);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse baseline JSON: {}", e);
                    }
                },
                Err(e) => {
                    eprintln!("Failed to read baseline file: {}", e);
                }
            }
        }
    }
}
