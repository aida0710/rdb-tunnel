use crate::packet::analysis::{AnalyzeResult, PacketAnalyzer};
use crate::packet::repository::PacketRepository;
use crate::packet::writer::error::WriterError;
use crate::packet::writer::PacketBuffer;
use log::{debug, error, info, trace};
use tokio::time::{interval, Duration};

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

pub struct PacketWriter {
    buffer: PacketBuffer,
    analyzer: PacketAnalyzer,
}

impl Default for PacketWriter {
    fn default() -> Self {
        Self {
            buffer: PacketBuffer::default(),
            analyzer: PacketAnalyzer::new(),
        }
    }
}

impl PacketWriter {
    pub async fn start(&self) {
        info!("パケットライターを開始します");
        let mut interval_timer = interval(FLUSH_INTERVAL);

        loop {
            interval_timer.tick().await;
            if let Err(e) = self.flush_buffer().await {
                error!("バッファのフラッシュに失敗しました: {}", e);
            }
        }
    }

    async fn flush_buffer(&self) -> Result<(), WriterError> {
        let packets = self.buffer.drain().await;
        if packets.is_empty() {
            return Ok(());
        }

        let start = std::time::Instant::now();
        match PacketRepository::bulk_insert(packets).await {
            Ok(_) => {
                let duration = start.elapsed();
                debug!("フラッシュ完了: 処理時間 {}ms", duration.as_millis());
                Ok(())
            }
            Err(e) => Err(WriterError::PacketBufferFlushError(e.to_string())),
        }
    }

    pub async fn process_packet(&self, ethernet_frame: &[u8]) -> Result<(), WriterError> {
        match self.analyzer.analyze_packet(ethernet_frame).await {
            AnalyzeResult::Accept(packet_data) => {
                trace!("書き込まれるパケット: {:?}", packet_data);
                self.buffer.push(packet_data).await;
                Ok(())
            }
            AnalyzeResult::Reject => {
                trace!("パケットが拒否されました");
                Ok(())
            }
        }
    }
}
