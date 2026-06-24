use log::error;
use std::io::Write;

const LOG_FILE_PATH: &str = "/var/log/nginx/cashu_redemption.log";

/// Helper function to log Cashu redemption task messages to a dedicated file.
/// If file logging fails, errors are logged to the nginx error log.
///
/// `msg` is sanitised before writing: newline and carriage-return characters
/// are stripped to prevent log-injection attacks.
pub fn log_redemption(msg: &str) {
    // Strip characters that could be used for log injection:
    // - CR/LF: inject new log lines
    // - NUL: truncate log entries in some parsers
    // - ESC (0x1b): ANSI escape sequences that corrupt terminal/log viewers
    // - TAB: column-injection in tab-delimited log parsers
    let sanitised: String = msg
        .chars()
        .filter(|&c| c != '\n' && c != '\r' && c != '\0' && c != '\x1b' && c != '\t')
        .collect();

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
