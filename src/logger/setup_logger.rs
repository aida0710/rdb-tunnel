use crate::config::LoggerConfig;
use crate::logger::idps_logger;
use env_logger::{Builder, Target};
use log::LevelFilter;
use std::io::Write;

pub fn setup_logger(logger_config: LoggerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let log_mode = match logger_config.idps_log_mode.as_str() {
        "all" => idps_logger::OutputMode::All,
        "file" => idps_logger::OutputMode::FileOnly,
        "console" => idps_logger::OutputMode::ConsoleOnly,
        "none" => idps_logger::OutputMode::None,
        _ => idps_logger::OutputMode::All,
    };

    // IDPSロガーの設定
    idps_logger::set_idps_settings(log_mode, &format!("../../{}", logger_config.idps_logger_file), &*logger_config.idps_path_style).expect("IDPSロガーの設定に失敗しました");

    Builder::new()
        .filter_level(LevelFilter::Info)
        .format(move |buf, record| {
            writeln!(
                buf,
                "{} [{}] {}:{} - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                match logger_config.normal_path_style.as_str() {
                    "file_path" => record.file().unwrap_or("file_pathが取得できませんでした"),
                    "module_path" => record.module_path().unwrap_or("module_pathが取得できませんでした"),
                    "none" => "",
                    _ => record.file().unwrap_or("file_pathが取得できませんでした"),
                },
                record.line().unwrap_or(0),
                record.args(),
            )
        })
        .target(Target::Stdout)
        .init();

    Ok(())
}
