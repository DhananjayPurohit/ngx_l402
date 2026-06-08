use log::error;
use std::io::Write;

const LOG_FILE_PATH: &str = "/var/log/nginx/cashu_redemption.log";

/// Helper function to log Cashu redemption task messages to a dedicated file.
/// If file logging fails, errors are logged to the nginx error log.
///
/// `msg` is sanitised before writing: newline and carriage-return characters
/// are stripped to prevent log-injection attacks (CWE-117).
pub fn log_redemption(msg: &str) {
    // Strip CR/LF so a crafted message cannot inject fake log lines.
    let sanitised = msg.replace(['\n', '\r'], "");

    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE_PATH)
    {
        Ok(mut file) => {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
            if let Err(e) = writeln!(file, "[{}] {}", timestamp, sanitised) {
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
