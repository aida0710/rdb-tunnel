use crate::config::error::ConfigError;
use dotenv::dotenv;

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub docker_mode: bool,
    pub docker_interface_name: String,
}

#[derive(Debug, Clone)]
pub struct LoggerConfig {
    pub normal_logger_file: String,
    pub idps_logger_file: String,
    pub idps_log_mode: String,
    pub normal_path_style: String,
    pub idps_path_style: String,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub node_id: i16,
    pub database: DatabaseConfig,
    pub network: NetworkConfig,
    pub logger_config: LoggerConfig,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        dotenv().map_err(|e| ConfigError::EnvFileReadError(e.to_string()))?;

        let get_env_var =
            |var_name: &str| -> Result<String, ConfigError> { dotenv::var(var_name).map_err(|e| ConfigError::EnvVarError(format!("{}: {}", var_name, e.to_string()))) };

        Ok(Self {
            node_id: {
                let value = get_env_var("NODE_ID")?.parse::<u16>().map_err(|e| ConfigError::EnvVarParseError(format!("NODE_ID: {}", e.to_string())))?;
                i16::try_from(value).map_err(|_| ConfigError::EnvVarParseError("NODE_ID: value exceeds i16::MAX".to_string()))?
            },
            database: DatabaseConfig {
                host: get_env_var("TIMESCALE_DB_HOST")?,
                port: get_env_var("TIMESCALE_DB_PORT")?.parse::<u16>().map_err(|e| ConfigError::EnvVarParseError(format!("TIMESCALE_DB_PORT: {}", e.to_string())))?,
                user: get_env_var("TIMESCALE_DB_USER")?,
                password: get_env_var("TIMESCALE_DB_PASSWORD")?,
                database: get_env_var("TIMESCALE_DB_DATABASE")?,
            },
            network: NetworkConfig {
                docker_mode: dotenv::var("DOCKER_MODE").map(|v| v.to_lowercase() == "true").unwrap_or(false),
                docker_interface_name: get_env_var("DOCKER_INTERFACE_NAME")?,
            },
            logger_config: LoggerConfig {
                normal_logger_file: get_env_var("NORMAL_LOGGER_FILE")?,
                idps_logger_file: get_env_var("IDPS_LOGGER_FILE")?,
                idps_log_mode: get_env_var("IDPS_LOG_MODE")?,
                normal_path_style: get_env_var("NORMAL_PATH_STYLE")?,
                idps_path_style: get_env_var("IDPS_PATH_STYLE")?,
            },
        })
    }
}
