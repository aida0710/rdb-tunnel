use crate::packet::monitor::error::MonitorError;
use crate::packet::writer::PacketWriter;
use log::{debug, error, info};
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct InterfaceHandler {
    interface: NetworkInterface,
}

impl InterfaceHandler {
    pub fn new(interface: NetworkInterface) -> Self {
        Self { interface }
    }

    pub async fn start(&self) -> Result<(), MonitorError> {
        let (_, mut rx) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(MonitorError::UnsupportedChannelType),
            Err(e) => return Err(MonitorError::NetworkError(e.to_string())),
        };

        info!("インターフェース {} でパケット受信を開始", self.interface.name);
        let writer = Arc::new(PacketWriter::default());

        // パケット処理用のチャネルを作成
        let (packet_tx, mut packet_rx) = mpsc::channel(1000);

        // パケット受信用のタスクを起動
        let receive_handle = tokio::spawn(async move {
            loop {
                match rx.next() {
                    Some(Ok(ethernet_frame)) => {
                        if packet_tx.send(ethernet_frame.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        error!("パケット読み取りエラー: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            Ok::<(), MonitorError>(())
        });

        // パケット処理用のタスクを起動
        let process_handle = tokio::spawn({
            let writer = Arc::clone(&writer);
            async move {
                while let Some(ethernet_data) = packet_rx.recv().await {
                    let writer_clone = Arc::clone(&writer);
                    if let Err(e) = Self::process_packet(&writer_clone, &ethernet_data).await {
                        error!("パケット処理中にエラーが発生しました: {}", e);
                    }
                }
                Ok::<(), MonitorError>(())
            }
        });

        // 両方のタスクが終了するのを待つ
        let (receive_result, process_result) = tokio::join!(receive_handle, process_handle);

        // エラーハンドリング
        match (receive_result, process_result) {
            (Ok(Ok(())), Ok(Ok(()))) => Ok(()),
            (Ok(Err(e)), _) | (_, Ok(Err(e))) => Err(e),
            (Err(e), _) | (_, Err(e)) => Err(MonitorError::ProcessingError(e.to_string())),
        }
    }

    async fn process_packet(writer: &PacketWriter, ethernet_data: &[u8]) -> Result<(), MonitorError> {
        if ethernet_data.len() < 14 {
            return Err(MonitorError::InvalidPacketSize);
        }

        let ether_type = u16::from_be_bytes([ethernet_data[12], ethernet_data[13]]);
        debug!("EtherType: 0x{:04x}", ether_type);

        writer.process_packet(ethernet_data).await
            .map_err(|e| MonitorError::ProcessingError(e.to_string()))
    }
}