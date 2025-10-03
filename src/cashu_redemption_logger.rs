use std::io::Write;

const LOG_FILE_PATH: &str = "/var/log/nginx/cashu_redemption.log";

/// Helper function to log Cashu redemption task messages to a dedicated file
pub fn log_redemption(msg: &str) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE_PATH) {
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(file, "[{}] {}", timestamp, msg);
    }
}

