use crate::config::AppConfig;
use crate::packet::reader::error::PacketReaderError;
use crate::packet::reader::packet_sender::PacketSender;
use crate::packet::repository::PacketRepository;
use futures::future::join_all;
use log::error;
use pnet::datalink::NetworkInterface;
use std::time::Duration;

#[derive(Clone)]
pub struct PacketReader {}

impl PacketReader {
    pub async fn start(interface: NetworkInterface) -> Result<(), PacketReaderError> {
        let config: AppConfig = AppConfig::new().map_err(|e| PacketReaderError::ConfigurationError(e.to_string()))?;

        loop {
            match PacketRepository::get_filtered_packets(config.node_id, false, None).await {
                Ok(packets) => {
                    let sends = packets.into_iter().map(|raw_packet| {
                        let interface_clone = interface.clone();
                        tokio::spawn(async move {
                            if let Err(e) = PacketSender::send_packet(&interface_clone, raw_packet).await {
                                error!("パケットの送信に失敗しました: {:?}", e);
                            }
                        })
                    });

                    join_all(sends).await;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                },
                Err(e) => {
                    error!("パケットの取得に失敗しました: {:?}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                },
            }
        }
    }
}
