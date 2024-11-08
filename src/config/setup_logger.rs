use crate::config::error::ConfigError;
use env_logger::{Builder, Target};
use log::LevelFilter;
use std::fs::File;
use std::io::Write;

pub fn setup_logger() -> Result<(), Box<dyn std::error::Error>> {
    let file: File = File::create("../../application.log").map_err(|e| ConfigError::LogFileCreateError(e.to_string()))?;

    Builder::new()
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {} - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .target(Target::Pipe(Box::new(file)))
        .target(Target::Stdout)
        .init();

    Ok(())
}