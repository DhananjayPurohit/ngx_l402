use log::error;
use std::io::Write;

const LOG_FILE_PATH: &str = "/var/log/nginx/cashu_redemption.log";

/// Helper function to log Cashu redemption task messages to a dedicated file
/// If file logging fails, errors are logged to nginx error log
pub fn log_redemption(msg: &str) {
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE_PATH)
    {
        Ok(mut file) => {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            if let Err(e) = writeln!(file, "[{}] {}", timestamp, msg) {
                error!("Failed to write to cashu redemption log: {}", e);
            }
        }
        Err(e) => {
            error!(
                "Failed to open cashu redemption log file {}: {}",
                LOG_FILE_PATH, e
            );
        }
    }
}
