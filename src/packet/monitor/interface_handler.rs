use crate::packet::monitor::error::MonitorError;
use crate::packet::writer::PacketWriter;
use log::{error, info};
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
        let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(80000);

        // パケット受信用のタスクを起動
        let receive_handle = tokio::spawn(async move {
            loop {
                match rx.next() {
                    Ok(ethernet_frame) => {
                        if packet_tx.send(ethernet_frame.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("パケット読み取りエラー: {}", e);
                        break;
                    }
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

                    let result = Self::process_packet(&writer_clone, &ethernet_data).await;

                    match result {
                        Ok(_) => log::debug!("パケット処理成功"),
                        Err(e) => log::error!("パケット処理エラー: {:?}", e),
                    }
                }
                Ok::<(), MonitorError>(())
            }
        });

        let (receive_result, process_result) = tokio::join!(receive_handle, process_handle);

        match (receive_result, process_result) {
            (Ok(Ok(())), Ok(Ok(()))) => Ok(()),
            (Ok(Err(e)), _) | (_, Ok(Err(e))) => Err(e),
            (Err(e), _) | (_, Err(e)) => Err(MonitorError::ProcessingError(e.to_string())),
        }
    }

    async fn process_packet(
        writer: &PacketWriter,
        ethernet_data: &[u8],
    ) -> Result<(), MonitorError> {
        writer.process_packet(ethernet_data).await.map_err(|e| {
            error!("パケット処理中にエラーが発生しました: {}", e);
            MonitorError::ProcessingError(e.to_string())
        })
    }
}
