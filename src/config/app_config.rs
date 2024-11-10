use crate::config::error::ConfigError;
use dotenv::dotenv;
use crate::config::idps::{DetectionRules, FTPViolation, FragmentViolation, ICMPViolation, IDPSConfig, IPHeaderViolation, IPOptionViolation, TCPViolation, UDPViolation};

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
    pub idps: IDPSConfig,
}

impl AppConfig {
    pub fn new() -> Result<Self, ConfigError> {
        dotenv().map_err(|e| ConfigError::EnvFileReadError(e.to_string()))?;

        Ok(Self {
            database: DatabaseConfig {
                host: dotenv::var("TIMESCALE_DB_HOST").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                port: dotenv::var("TIMESCALE_DB_PORT").map_err(|e| ConfigError::EnvVarError(e.to_string()))?.parse::<u16>().map_err(|e| ConfigError::EnvVarParseError(e.to_string()))?,
                user: dotenv::var("TIMESCALE_DB_USER").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                password: dotenv::var("TIMESCALE_DB_PASSWORD").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                database: dotenv::var("TIMESCALE_DB_DATABASE").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
            },
            network: NetworkConfig {
                tap_ip: dotenv::var("TAP_IP").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                tap_mask: dotenv::var("TAP_MASK").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                tap_interface_name: dotenv::var("TAP_INTERFACE_NAME").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
                docker_mode: dotenv::var("DOCKER_MODE").map(|v| v.to_lowercase() == "true").unwrap_or(false),
                docker_interface_name: dotenv::var("DOCKER_INTERFACE_NAME").map_err(|e| ConfigError::EnvVarError(e.to_string()))?,
            },
            idps: IDPSConfig {
                enabled: dotenv::var("IDPS_ENABLED").map(|v| v.to_lowercase() == "true").unwrap_or(false),
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
                        FragmentViolation::FragmentStorm,
                        FragmentViolation::LargeOffset,
                        FragmentViolation::TooManyFragments,
                        FragmentViolation::Teardrop,
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
                    udp: vec![
                        UDPViolation::ShortHeader,
                        UDPViolation::Bomb,
                    ],
                    tcp: vec![
                        TCPViolation::NoBitsSet,
                        TCPViolation::SynAndFin,
                        TCPViolation::FinNoAck,
                    ],
                    ftp: vec![
                        FTPViolation::ImproperPort,
                    ],
                },
                log_violations: dotenv::var("IDPS_LOG").map(|v| v.to_lowercase() == "true").unwrap_or(false),
                block_violations: dotenv::var("IDPS_BLOCK").map(|v| v.to_lowercase() == "true").unwrap_or(false),
            }

        })
    }
}
