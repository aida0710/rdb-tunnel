use crate::config::AppConfig;
use crate::packet::analysis::{AnalyzeResult, PacketAnalyzer};
use crate::packet::repository::PacketRepository;
use crate::packet::writer::error::WriterError;
use crate::packet::writer::PacketBuffer;
use log::{error, info, trace};
use tokio::time::{interval, Duration};

const FLUSH_INTERVAL: Duration = Duration::from_millis(10);

pub struct PacketWriter {
    buffer: PacketBuffer,
}

impl Default for PacketWriter {
    fn default() -> Self {
        Self { buffer: PacketBuffer::default() }
    }
}

impl PacketWriter {
    pub async fn start(&self) -> Result<(), WriterError> {
        info!("パケットライターを開始します");
        let mut interval_timer = interval(FLUSH_INTERVAL);

        let config: AppConfig = AppConfig::new().map_err(|e| WriterError::ConfigurationError(e.to_string()))?;

        loop {
            interval_timer.tick().await;
            if let Err(e) = self.flush_buffer(config.node_id).await {
                error!("バッファのフラッシュに失敗しました: {}", e);
            }
        }
    }

    async fn flush_buffer(&self, node_id: i16) -> Result<(), WriterError> {
        let packets = self.buffer.drain().await;
        if packets.is_empty() {
            return Ok(());
        }

        let start = std::time::Instant::now();
        match PacketRepository::bulk_insert(node_id, packets).await {
            Ok(_) => {
                let duration = start.elapsed();
                info!("フラッシュ完了: 処理時間 {}ms", duration.as_millis());
                Ok(())
            },
            Err(e) => Err(WriterError::PacketBufferFlushError(e.to_string())),
        }
    }

    pub async fn process_packet(&self, ethernet_frame: &[u8]) -> Result<(), WriterError> {
        match PacketAnalyzer::analyze_packet(ethernet_frame).await {
            AnalyzeResult::Accept(packet_data) => {
                self.buffer.push(packet_data).await;
                Ok(())
            },
            AnalyzeResult::Reject => {
                trace!("パケットが拒否されました");
                Ok(())
            },
        }
    }
}
