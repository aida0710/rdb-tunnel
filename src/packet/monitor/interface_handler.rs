use crate::packet::monitor::error::MonitorError;
use crate::packet::writer::PacketWriter;
use log::{error, info};
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use std::time::Duration;

const READ_BUFFER_SIZE: usize = 65536;
const WRITE_BUFFER_SIZE: usize = 65536;
const READ_TIMEOUT: Duration = Duration::from_secs(1);

pub struct InterfaceHandler {
    interface: NetworkInterface,
}

impl InterfaceHandler {
    pub fn new(interface: NetworkInterface) -> Self {
        Self { interface }
    }

    pub async fn start(&self) -> Result<(), MonitorError> {
        let config = Config {
            write_buffer_size: WRITE_BUFFER_SIZE,
            read_buffer_size: READ_BUFFER_SIZE,
            read_timeout: Some(READ_TIMEOUT),
            write_timeout: None,
            channel_type: datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: true,
            socket_fd: None,
        };

        let (_, mut rx) = match datalink::channel(&self.interface, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(MonitorError::UnsupportedChannelType),
            Err(e) => return Err(MonitorError::NetworkError(e.to_string())),
        };

        info!("インターフェース {} でパケット受信を開始", self.interface.name);
        let writer = PacketWriter::default();

        loop {
            match rx.next() {
                Ok(ethernet_frame) => {
                    if let Err(e) = writer.process_packet(&ethernet_frame).await {
                        error!("パケット処理エラー: {}", e);
                    }
                },
                Err(e) => {
                    if e.to_string() == "Timed out" {
                        continue;
                    }
                    error!("パケット読み取りエラー: {}", e);
                    break;
                },
            }
        }

        Ok(())
    }
}
