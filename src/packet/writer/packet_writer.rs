use crate::database::DbError;
use crate::packet::firewall::{Filter, FirewallPacket, IpFirewall, Policy};
use crate::packet::repository::PacketRepository;
use crate::packet::writer::{PacketAnalyzer, PacketBuffer};
use lazy_static::lazy_static;
use log::{debug, error, info, trace};
use std::net::IpAddr;
use tokio::time::{interval, Duration};

const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

lazy_static! {
    static ref FIREWALL: IpFirewall = {
        let mut fw = IpFirewall::new(Policy::Blacklist);
        fw.add_rule(Filter::DstIpAddress("160.251.175.134".parse().unwrap()), 100);
        fw.add_rule(Filter::DstPort(13432), 90);
        fw.add_rule(Filter::DstPort(2222), 80);
        fw
    };
}

pub struct PacketWriter {
    buffer: PacketBuffer,
}

impl Default for PacketWriter {
    fn default() -> Self {
        Self {
            buffer: PacketBuffer::default(),
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

    async fn flush_buffer(&self) -> Result<(), DbError> {
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
            Err(e) => {
                error!("パケットバッファのフラッシュに失敗しました: {}", e);
                Err(e)
            }
        }
    }

    pub async fn process_packet(&self, ethernet_packet: &[u8]) -> Result<(), DbError> {
        if ethernet_packet.len() < 14 {
            error!("無効なイーサネットパケット長");
            return Ok(());
        }

        match PacketAnalyzer::analyze_packet(ethernet_packet).await {
            Ok(packet_data) => {
                let packet = packet_data.to_packet();
                let firewall_packet = FirewallPacket::from_packet(&packet);
                if FIREWALL.check(&firewall_packet) {
                    trace!("許可：firewall_packet: {}:{} -> {}:{}",
                        packet_data.src_ip.0, packet_data.src_port,
                        packet_data.dst_ip.0, packet_data.dst_port
                    );
                    self.buffer.push(packet_data).await;
                } else {
                    trace!("不許可：firewall_packet: {}:{} -> {}:{}",
                        packet_data.src_ip.0, packet_data.src_port,
                        packet_data.dst_ip.0, packet_data.dst_port
                    );
                }
                Ok(())
            }
            Err(e) => {
                error!("パケット解析エラー: {}", e);
                Err(e)
            }
        }
    }
}