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
    idps_logger::set_log_file(&format!("../../{}", logger_config.idps_logger_file))?;
    idps_logger::set_output_mode(log_mode);

    // 通常のロガーの設定
    /*let file: File = File::create(format!("../../{}", logger_config.normal_logger_file))
    .map_err(|e| LoggerError::LogFileCreateError(e.to_string()))?;*/

    Builder::new()
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {} L:{} - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.target(),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        //.target(Target::Pipe(Box::new(file)))
        .target(Target::Stdout)
        .init();

    Ok(())
}
