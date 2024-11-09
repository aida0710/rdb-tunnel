use crate::packet::monitor::error::MonitorError;
use crate::packet::monitor::interface_handler::InterfaceHandler;
use log::info;
use pnet::datalink::NetworkInterface;

pub struct NetworkMonitor;

impl NetworkMonitor {
    pub async fn start_monitoring(interface: NetworkInterface) -> Result<(), MonitorError> {
        let interfaces = pnet::datalink::interfaces();
        let tap0_interface = Self::find_tap0_interface(&interfaces)?;
        info!("ネットワークのモニタリングを開始します");

        let main_handler = InterfaceHandler::new(interface);
        let tap_handler = InterfaceHandler::new(tap0_interface);

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
        Ok(())
    }

    fn find_tap0_interface(interfaces: &[NetworkInterface]) -> Result<NetworkInterface, MonitorError> {
        interfaces
            .iter()
            .find(|interface| interface.name == "tap0")
            .cloned()
            .ok_or_else(|| MonitorError::InterfaceNotFound(String::from("tap0")))
    }
}