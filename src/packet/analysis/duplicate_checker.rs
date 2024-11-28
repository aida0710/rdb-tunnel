use crate::packet::analysis::AnalyzeResult;
use log::debug;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct DuplicateChecker {
    packet_history: HashSet<PacketIdentifier>,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct PacketIdentifier {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    frame_content: Vec<u8>,
}

impl DuplicateChecker {
    pub fn new() -> Self {
        Self {
            packet_history: HashSet::new(),
            cleanup_interval: Duration::from_secs(5),
            last_cleanup: Instant::now(),
        }
    }

    pub fn check_packet(&mut self, ethernet_frame: &[u8]) -> Option<AnalyzeResult> {
        self.maybe_cleanup();

        if let Some(identifier) = self.extract_packet_identifier(ethernet_frame) {
            // すでに履歴にあれば重複
            if self.packet_history.contains(&identifier) {
                debug!("重複パケットを検出: src={}, dst={}", identifier.src_ip, identifier.dst_ip);
                return Some(AnalyzeResult::Reject);
            }

            // 新規パケットを履歴に追加
            debug!("新規パケットを検出: src={}, dst={}", identifier.src_ip, identifier.dst_ip);
            self.packet_history.insert(identifier);
        }

        None
    }

    fn extract_packet_identifier(&self, frame: &[u8]) -> Option<PacketIdentifier> {
        if frame.len() < 34 {
            return None;
        }

        let src_ip = self.extract_ip_address(&frame[26..30]);
        let dst_ip = self.extract_ip_address(&frame[30..34]);

        Some(PacketIdentifier {
            src_ip,
            dst_ip,
            frame_content: frame.to_vec(),
        })
    }

    fn extract_ip_address(&self, bytes: &[u8]) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }

    fn maybe_cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= self.cleanup_interval {
            self.cleanup();
        }
    }

    fn cleanup(&mut self) {
        let size_before = self.packet_history.len();
        self.packet_history.clear();
        self.last_cleanup = Instant::now();
        debug!("パケット履歴をクリーンアップ: {} エントリを削除", size_before);
    }
}
