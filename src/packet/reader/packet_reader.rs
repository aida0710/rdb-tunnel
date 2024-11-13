use crate::packet::reader::error::PacketReaderError;
use crate::packet::reader::packet_sender::PacketSender;
use crate::packet::repository::PacketRepository;
use crate::packet::Packet;
use log::{debug, error, info};
use pnet::datalink::NetworkInterface;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct PacketReader {
    last_timestamp: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    is_first_poll: Arc<AtomicBool>,
    interface: Arc<NetworkInterface>,
    packets_sent: Arc<AtomicU64>,
    packets_failed: Arc<AtomicU64>,
}

impl PacketReader {
    pub fn new(interface: NetworkInterface) -> Self {
        Self {
            last_timestamp: Arc::new(Mutex::new(None)),
            is_first_poll: Arc::new(AtomicBool::new(true)),
            interface: Arc::new(interface),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_failed: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn poll_packets(&self) -> Result<Vec<Packet>, PacketReaderError> {
        let mut last_ts = self.last_timestamp.lock().await;
        let is_first = self.is_first_poll.load(Ordering::SeqCst);
        let current_time = chrono::Utc::now();

        let packets = PacketRepository::get_filtered_packets(
            is_first,
            last_ts.as_ref(),
        ).await.map_err(|e| PacketReaderError::FilteredPacketsFetchError(e))?;

        if let Some(packet) = packets.last() {
            *last_ts = Some(packet.timestamp);
        } else {
            *last_ts = Some(current_time);
        }

        if is_first {
            self.is_first_poll.store(false, Ordering::SeqCst);
            info!("初回ポーリング完了、フラグを更新しました");
        }

        Ok(packets.into_iter().collect())
    }

    pub async fn poll_and_send_packets(&self) -> Result<(), PacketReaderError> {
        match self.poll_packets().await {
            Ok(packets) => {
                let packet_count = packets.len();
                debug!("{}個のパケットを取得しました", packet_count);

                for packet in packets {
                    if let Err(e) = PacketSender::send_packet(&self.interface, &packet).await {
                        error!("パケット送信エラー: {}", e);
                        self.packets_failed.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }
                    self.packets_sent.fetch_add(1, Ordering::SeqCst);
                }

                let sent = self.packets_sent.load(Ordering::SeqCst);
                let failed = self.packets_failed.load(Ordering::SeqCst);
                info!("パケット処理完了 - 成功: {}, 失敗: {}", sent, failed);

                self.packets_sent.store(0, Ordering::SeqCst);
                self.packets_failed.store(0, Ordering::SeqCst);

                Ok(())
            }
            Err(e) => {
                error!("ポーリングとパケット送信中のエラー: {:?}", e);
                Err(PacketReaderError::PollingAndSendingError(e.to_string()))
            }
        }
    }
}

pub async fn inject_packet(interface: NetworkInterface) -> Result<(), PacketReaderError> {
    let my_ip = interface.ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| ip.ip())
        .ok_or_else(|| PacketReaderError::InterfaceIpv4AddressNotFound(interface.to_string()))?;

    info!("パケット転送を開始します: {}", my_ip);

    let poller = PacketReader::new(interface);
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));

    loop {
        interval.tick().await;
        if let Err(e) = poller.poll_and_send_packets().await {
            error!("パケット処理中にエラーが発生しました: {:?}", e);
            Err(PacketReaderError::InjectPacketUnexpectedError(e.to_string()))?;
        }
    }
}