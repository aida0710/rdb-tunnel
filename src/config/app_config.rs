use crate::config::error::ConfigError;
use crate::config::idps::{DetectionRules, FTPViolation, FragmentViolation, ICMPViolation, IDPSConfig, IPHeaderViolation, IPOptionViolation, TCPViolation, UDPViolation};
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
    pub use_tap_interface: bool,
    pub tap_ip: String,
    pub tap_mask: String,
    pub tap_interface_name: String,
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
    pub idps: IDPSConfig,
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
                use_tap_interface: dotenv::var("USE_TAP_INTERFACE").map(|v| v.to_lowercase() == "true").unwrap_or(false),
                tap_ip: get_env_var("TAP_IP")?,
                tap_mask: get_env_var("TAP_MASK")?,
                tap_interface_name: get_env_var("TAP_INTERFACE_NAME")?,
                docker_mode: dotenv::var("DOCKER_MODE").map(|v| v.to_lowercase() == "true").unwrap_or(false),
                docker_interface_name: get_env_var("DOCKER_INTERFACE_NAME")?,
            },
            idps: IDPSConfig {
                enabled: dotenv::var("IDS_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(false),
                rules: DetectionRules {
                    ip_header: vec![
                        IPHeaderViolation::UnknownProtocol,
                        IPHeaderViolation::LandAttack,
                        IPHeaderViolation::ShortHeader,
                        IPHeaderViolation::MalformedPacket,
                    ],
                    ip_option: vec![
                        IPOptionViolation::MalformedOption,
                        IPOptionViolation::SecurityOption,
                        IPOptionViolation::LooseRouting,
                        IPOptionViolation::RecordRoute,
                        IPOptionViolation::StreamId,
                        IPOptionViolation::StrictRouting,
                        IPOptionViolation::Timestamp,
                    ],
                    fragment: vec![
                        FragmentViolation::LargeOffset,
                        FragmentViolation::SameOffset,
                        FragmentViolation::InvalidFragment,
                    ],
                    icmp: vec![
                        ICMPViolation::SourceQuench,
                        ICMPViolation::TimestampRequest,
                        ICMPViolation::TimestampReply,
                        ICMPViolation::InfoRequest,
                        ICMPViolation::InfoReply,
                        ICMPViolation::MaskRequest,
                        ICMPViolation::MaskReply,
                        ICMPViolation::TooLarge,
                    ],
                    udp: vec![UDPViolation::ShortHeader, UDPViolation::Bomb],
                    tcp: vec![TCPViolation::NoBitsSet, TCPViolation::SynAndFin, TCPViolation::FinNoAck],
                    ftp: vec![FTPViolation::ImproperPort],
                },
                block_violations: dotenv::var("IPS_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(false),
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
