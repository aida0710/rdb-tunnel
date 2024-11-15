use crate::logger::error::LoggerError;
use chrono::Local;
use once_cell::sync::Lazy;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    All,
    FileOnly,
    ConsoleOnly,
    None,
}

struct LogConfig {
    file: Option<Mutex<File>>,
    mode: OutputMode,
    file_path: Option<String>,
}

static LOGGER: Lazy<Mutex<LogConfig>> = Lazy::new(|| {
    Mutex::new(LogConfig {
        file: None,
        mode: OutputMode::All,
        file_path: None,
    })
});

fn create_log_file(file_path: &str) -> Result<File, LoggerError> {
    let path = Path::new(file_path);

    // 親ディレクトリが存在するか確認し、存在しなければ作成する
    if let Some(parent) = path.parent() {
        if parent.exists() {
            println!("ディレクトリが既に存在します: {}", parent.display());
        } else {
            if let Err(e) = fs::create_dir_all(parent) {
                return Err(LoggerError::LogFileCreateError(e.to_string()));
            }
            println!("ディレクトリを作成しました: {}", parent.display());
        }
    }

    match OpenOptions::new().create(true).append(true).open(file_path) {
        Ok(file) => {
            println!("ファイルを作成または開きました: {}", file_path);
            Ok(file)
        }
        Err(e) => Err(LoggerError::LogFileCreateError(e.to_string())),
    }
}

pub fn set_output_mode(mode: OutputMode) {
    if let Ok(mut logger) = LOGGER.lock() {
        logger.mode = mode;

        if (mode == OutputMode::FileOnly || mode == OutputMode::All) && logger.file.is_none() {
            // ファイルパスが設定されている場合のみファイルを作成
            if let Some(path) = &logger.file_path {
                logger.file = create_log_file(path).ok().map(Mutex::new);
            }
        }
    }
}

pub fn set_log_file(file_path: &str) -> Result<(), LoggerError> {
    if let Ok(mut logger) = LOGGER.lock() {
        logger.file_path = Some(file_path.to_string());

        // ファイルモードが有効な場合は新しいファイルを作成
        if logger.mode == OutputMode::FileOnly || logger.mode == OutputMode::All {
            logger.file = create_log_file(file_path).ok().map(Mutex::new);
        }
        Ok(())
    } else {
        Err(LoggerError::LogFileCreateError(
            "Failed to lock logger".to_string(),
        ))
    }
}

pub fn write_log(message: &str, file: &str, line: u32) {
    if let Ok(logger) = LOGGER.lock() {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let log_message = format!("[{}] [{}/{}] {}\n", timestamp, file, line, message);

        match logger.mode {
            OutputMode::All | OutputMode::FileOnly => {
                if let Some(file_mutex) = &logger.file {
                    if let Ok(mut file) = file_mutex.lock() {
                        let _ = file.write_all(log_message.as_bytes());
                        let _ = file.flush();
                    }
                }
            }
            _ => {}
        }

        match logger.mode {
            OutputMode::All | OutputMode::ConsoleOnly => {
                print!("{}", log_message);
            }
            _ => {}
        }
    }
}

#[macro_export]
macro_rules! idps_log {
    ($($arg:tt)*) => {{
        $crate::logger::idps_logger::write_log(
            &format!($($arg)*),
            file!(),
            line!()
        );
    }};
}
