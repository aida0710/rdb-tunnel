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
    pub tap_ip: String,
    pub tap_mask: String,
    pub tap_interface_name: String,
    pub docker_mode: bool,
    pub docker_interface_name: String,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub network: NetworkConfig,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        dotenv().map_err(|e| ConfigError::EnvFileReadError(e.to_string()))?;

        Ok(Self {
            database: DatabaseConfig {
                host: dotenv::var("TIMESCALE_DB_HOST").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                port: dotenv::var("TIMESCALE_DB_PORT")
                    .map_err(|e| ConfigError::EnvVarError(e.to_string()))?
                    .parse::<u16>()
                    .map_err(|e| ConfigError::EnvVarParseError(e.to_string()))?,
                user: dotenv::var("TIMESCALE_DB_USER").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                password: dotenv::var("TIMESCALE_DB_PASSWORD").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                database: dotenv::var("TIMESCALE_DB_DATABASE").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
            },
            network: NetworkConfig {
                tap_ip: dotenv::var("TAP_IP").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                tap_mask: dotenv::var("TAP_MASK").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                tap_interface_name: dotenv::var("TAP_INTERFACE_NAME").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                docker_mode: dotenv::var("DOCKER_MODE")
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false),
                docker_interface_name: dotenv::var("DOCKER_INTERFACE_NAME").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
            },
        })
    }
}
