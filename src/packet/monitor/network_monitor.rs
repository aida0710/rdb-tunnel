use crate::packet::monitor::error::MonitorError;
use crate::packet::monitor::interface_handler::InterfaceHandler;
use log::info;
use pnet::datalink::NetworkInterface;

pub struct NetworkMonitor;

impl NetworkMonitor {
    pub async fn start_monitoring(interface: NetworkInterface) -> Result<(), MonitorError> {
        let main_handler = InterfaceHandler::new(interface);

        info!("通常モードでネットワークのモニタリングを開始します");
        if let Err(e) = main_handler.start().await {
            return Err(MonitorError::MainInterfaceError(e.to_string()));
        }

        Ok(())
    }
}
