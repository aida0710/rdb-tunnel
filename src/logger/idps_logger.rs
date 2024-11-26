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

pub struct LogConfig {
    file: Option<Mutex<File>>,
    mode: OutputMode,
    file_path: Option<String>,
    path_style: Option<String>,
}

static LOGGER: Lazy<Mutex<LogConfig>> = Lazy::new(|| {
    Mutex::new(LogConfig {
        file: None,
        mode: OutputMode::All,
        file_path: None,
        path_style: None,
    })
});

fn create_log_file(file_path: &str) -> Result<File, LoggerError> {
    let path = Path::new(file_path);

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
        },
        Err(e) => Err(LoggerError::LogFileCreateError(e.to_string())),
    }
}

pub fn set_idps_settings(mode: OutputMode, file_path: &str, path_style: &str) -> Result<(), LoggerError> {
    if let Ok(mut logger) = LOGGER.lock() {
        logger.mode = mode;
        logger.file_path = Some(file_path.to_string());
        logger.path_style = Some(path_style.to_string());

        if mode == OutputMode::FileOnly || mode == OutputMode::All {
            logger.file = create_log_file(file_path).ok().map(Mutex::new);
        }

        Ok(())
    } else {
        Err(LoggerError::LoggerLockError("Loggerのロックに失敗しました".to_string()))
    }
}

pub fn write_log(message: &str, log_file_path: &str, module_path: &str, line: u32) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

    if let Ok(logger) = LOGGER.lock() {
        if logger.file_path.is_some() {
            let path_info = match logger.path_style.as_deref() {
                Some("file_path") => log_file_path,
                Some("module_path") => module_path,
                Some("none") => "",
                _ => log_file_path,
            };

            let final_log_message = format!("{} [IDPS] {}:{} - {}\n", timestamp, path_info, line, message);

            if matches!(logger.mode, OutputMode::All | OutputMode::FileOnly) {
                if let Some(file_mutex) = &logger.file {
                    if let Ok(mut file) = file_mutex.lock() {
                        let _ = file.write_all(final_log_message.as_bytes());
                        let _ = file.flush();
                    }
                }
            }

            if matches!(logger.mode, OutputMode::All | OutputMode::ConsoleOnly) {
                print!("{}", final_log_message);
            }
        }
    }
}

#[macro_export]
macro_rules! idps_log {
    ($($arg:tt)*) => {{
        $crate::logger::idps_logger::write_log(
            &format!($($arg)*),
            file!(),
            module_path!(),
            line!()
        );
    }};
}
