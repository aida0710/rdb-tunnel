use super::rules::*;

#[derive(Debug, Clone)]
pub struct IDPSConfig {
    pub enabled: bool,
    pub rules: DetectionRules,
    pub block_violations: bool,
}

impl Default for IDPSConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: DetectionRules {
                ip_header: vec![],
                ip_option: vec![],
                fragment: vec![],
                icmp: vec![],
                udp: vec![],
                tcp: vec![],
                ftp: vec![],
            },
            block_violations: true,
        }
    }
}
