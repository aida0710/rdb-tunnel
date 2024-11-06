use crate::error::InitProcessError;
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
    pub fn new() -> Result<Self, InitProcessError> {
        dotenv().map_err(|e| InitProcessError::EnvFileReadError(e.to_string()))?;

        Ok(Self {
            database: DatabaseConfig {
                host: get_env_var("TIMESCALE_DB_HOST").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
                port: get_env_var("TIMESCALE_DB_PORT")
                    .map_err(|e| InitProcessError::EnvVarError(e.to_string()))?
                    .parse::<u16>()
                    .map_err(|e| InitProcessError::EnvVarParseError(e.to_string()))?,
                user: get_env_var("TIMESCALE_DB_USER").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
                password: get_env_var("TIMESCALE_DB_PASSWORD").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
                database: get_env_var("TIMESCALE_DB_DATABASE").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
            },
            network: NetworkConfig {
                tap_ip: get_env_var("TAP_IP").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
                tap_mask: get_env_var("TAP_MASK").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
                tap_interface_name: get_env_var("TAP_INTERFACE_NAME").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
                docker_mode: get_env_var("DOCKER_MODE")
                    .map(|v| v.to_lowercase() == "true")
                    .unwrap_or(false),
                docker_interface_name: get_env_var("DOCKER_INTERFACE_NAME").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?,
            },
        })
    }
}

fn get_env_var(key: &str) -> Result<String, InitProcessError> {
    dotenv::var(key).map_err(|e| InitProcessError::EnvVarError(e.to_string()))
}