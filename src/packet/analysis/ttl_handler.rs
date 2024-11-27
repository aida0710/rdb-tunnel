use log::{debug, info};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct TtlHandler {
    min_ttl: u8,
    ttl_decrease: u8,
    packet_history: HashMap<PacketIdentifier, PacketState>,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct PacketIdentifier {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    frame_content: Vec<u8>,
}

struct PacketState {
    first_seen: Instant,
    ttl_history: Vec<u8>,
    processed_count: u32,
}

impl TtlHandler {
    pub fn new(min_ttl: u8, ttl_decrease: u8) -> Self {
        Self {
            min_ttl,
            ttl_decrease,
            packet_history: HashMap::new(),
            cleanup_interval: Duration::from_secs(30),
            last_cleanup: Instant::now(),
        }
    }

    pub fn process_packet(&mut self, ethernet_frame: &mut [u8]) -> bool {
        self.maybe_cleanup();

        if let Some(identifier) = self.extract_packet_identifier(ethernet_frame) {
            if self.is_duplicate_packet(&identifier, ethernet_frame) {
                debug!("重複パケットを検出: src={}, dst={}", identifier.src_ip, identifier.dst_ip);
                return false;
            }

            if !self.process_ttl(ethernet_frame) {
                return false;
            }

            self.update_packet_history(identifier, ethernet_frame);
            return true;
        }

        false
    }

    fn extract_packet_identifier(&self, frame: &[u8]) -> Option<PacketIdentifier> {
        if frame.len() < 34 {
            return None;
        }

        let src_ip = self.extract_ip_address(&frame[26..30]);
        let dst_ip = self.extract_ip_address(&frame[30..34]);

        // TTLフィールドを除いた完全なフレームのコピーを作成
        let mut frame_content = frame.to_vec();
        if frame_content.len() > 22 {
            // TTLフィールドをゼロに設定
            frame_content[22] = 0;
        }

        Some(PacketIdentifier { src_ip, dst_ip, frame_content })
    }

    fn extract_ip_address(&self, bytes: &[u8]) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }

    fn is_duplicate_packet(&self, identifier: &PacketIdentifier, frame: &[u8]) -> bool {
        // 完全一致パケットを検出
        if let Some(state) = self.packet_history.get(identifier) {
            let current_ttl = frame[22];

            // 短時間での同一パケットの検出
            if state.processed_count > 2 && state.first_seen.elapsed() < Duration::from_millis(300) {
                info!(
                    "短時間での同一パケット検出: src={}, dst={}, count={}",
                    identifier.src_ip, identifier.dst_ip, state.processed_count
                );
                return true;
            }

            // 同一パケットでのTTL値の不自然な変化を検出
            if !state.ttl_history.is_empty() {
                let last_ttl = state.ttl_history.last().unwrap();
                if current_ttl > *last_ttl {
                    info!(
                        "同一パケットでのTTL値の不自然な増加: src={}, dst={}, TTL: {} -> {}",
                        identifier.src_ip, identifier.dst_ip, last_ttl, current_ttl
                    );
                    return true;
                }
            }
        }

        false
    }

    fn process_ttl(&self, frame: &mut [u8]) -> bool {
        let current_ttl = frame[22];

        if current_ttl < self.min_ttl {
            debug!("TTLが最小値未満: {} < {}", current_ttl, self.min_ttl);
            return false;
        }

        // TTL値を減算して更新
        let new_ttl = current_ttl.saturating_sub(self.ttl_decrease);
        frame[22] = new_ttl;

        // IPヘッダのチェックサム再計算
        self.recalculate_checksum(&mut frame[14..34]);
        true
    }

    fn update_packet_history(&mut self, identifier: PacketIdentifier, frame: &[u8]) {
        let now = Instant::now();
        let entry = self.packet_history.entry(identifier).or_insert_with(|| PacketState {
            first_seen: now,
            ttl_history: Vec::new(),
            processed_count: 0,
        });

        entry.ttl_history.push(frame[22]);
        entry.processed_count += 1;
    }

    fn maybe_cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            self.cleanup();
            self.last_cleanup = now;
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.packet_history.retain(|_, state| now.duration_since(state.first_seen) < Duration::from_secs(60));
        info!("パケット履歴のクリーンアップ完了: {} エントリ", self.packet_history.len());
    }

    fn recalculate_checksum(&self, ip_header: &mut [u8]) {
        let mut sum = 0u32;
        // チェックサムフィールドを除いてヘッダの各16ビット値を加算
        for i in (0..20).step_by(2) {
            if i != 10 {
                sum += u16::from_be_bytes([ip_header[i], ip_header[i + 1]]) as u32;
            }
        }

        // 16ビットを超える桁は下位16ビットに加算
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // 1の補数を取ってチェックサムを設定
        let checksum = !sum as u16;
        ip_header[10..12].copy_from_slice(&checksum.to_be_bytes());
    }
}
