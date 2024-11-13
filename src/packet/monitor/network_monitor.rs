use crate::packet::monitor::error::MonitorError;
use crate::packet::monitor::interface_handler::InterfaceHandler;
use log::info;
use pnet::datalink::NetworkInterface;
use crate::config::AppConfig;

pub struct NetworkMonitor;

impl NetworkMonitor {
    pub async fn start_monitoring(interface: NetworkInterface) -> Result<(), MonitorError> {
        let config: AppConfig = AppConfig::new().map_err(|e| MonitorError::ConfigurationError(e.to_string()))?;

        let main_handler = InterfaceHandler::new(interface);

        if config.network.use_tap_interface {
            info!("TAP インターフェースを使用してネットワークのモニタリングを開始します");
            let interfaces = pnet::datalink::interfaces();
            let tap_interface = Self::find_tap_interface(&interfaces, config.network.tap_interface_name.as_str())?;
            let tap_handler = InterfaceHandler::new(tap_interface);

            tokio::select! {
                res = main_handler.start() => {
                    if let Err(e) = res {
                        return Err(MonitorError::MainInterfaceError(e.to_string()));
                    }
                }
                res = tap_handler.start() => {
                    if let Err(e) = res {
                        return Err(MonitorError::TapInterfaceError(e.to_string()));
                    }
                }
            }
        } else {
            info!("通常モードでネットワークのモニタリングを開始します");
            if let Err(e) = main_handler.start().await {
                return Err(MonitorError::MainInterfaceError(e.to_string()));
            }
        }

        Ok(())
    }

    fn find_tap_interface(interfaces: &[NetworkInterface], tap_interface_name: &str) -> Result<NetworkInterface, MonitorError> {
        interfaces
            .iter()
            .find(|interface| interface.name == tap_interface_name)
            .cloned()
            .ok_or_else(|| MonitorError::InterfaceNotFound(String::from(tap_interface_name)))
    }
}