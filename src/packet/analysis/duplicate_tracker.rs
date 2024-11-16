use crate::packet::types::EtherType;
use log::{debug, info, trace};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct PacketIdentifier {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    timestamp: u64,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct RawPacketIdentifier {
    data: Vec<u8>,
}

#[derive(Debug)]
struct PacketInfo {
    ether_type: EtherType,
    protocol: String,
    length: usize,
    first_detection: Instant,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    detect_count: u32,
}

pub struct PacketTracker {
    recent_packets: Arc<Mutex<HashSet<PacketIdentifier>>>,
    raw_packets: Arc<Mutex<HashMap<RawPacketIdentifier, (Instant, PacketInfo)>>>,
    broadcast_packets: Arc<Mutex<HashMap<RawPacketIdentifier, (Instant, PacketInfo)>>>,
    last_cleanup: Arc<Mutex<SystemTime>>,
}

impl PacketTracker {
    // 通常パケットは3秒
    const DUPLICATE_THRESHOLD: Duration = Duration::from_secs(3);
    // ブロードキャストやARPは10秒
    const BROADCAST_THRESHOLD: Duration = Duration::from_secs(10);

    pub fn new() -> Self {
        Self {
            recent_packets: Arc::new(Mutex::new(HashSet::new())),
            raw_packets: Arc::new(Mutex::new(HashMap::new())),
            broadcast_packets: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(SystemTime::now())),
        }
    }

    pub async fn is_duplicate(&self, raw_packet: &[u8], ether_type: EtherType) -> bool {
        let (src_mac, dst_mac) = extract_mac_addresses(raw_packet);

        if ether_type == EtherType::ARP || is_broadcast_or_multicast(raw_packet) {
            let mut broadcast_packets = self.broadcast_packets.lock().await;
            let identifier = RawPacketIdentifier {
                data: raw_packet.to_vec(),
            };

            let now = Instant::now();
            if let Some((last_seen, mut info)) = broadcast_packets.remove(&identifier) {
                if now.duration_since(last_seen) < Self::BROADCAST_THRESHOLD {
                    info.detect_count += 1; // カウントを増やす
                    info!(
                        "ブロードキャスト系パケットの重複を検出: 検出回数={}回目 タイプ={:?} プロトコル={} 長さ={} 経過時間={}ms 送信元MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} 宛先MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        info.detect_count, info.ether_type, info.protocol, info.length,
                        now.duration_since(info.first_detection).as_millis(),
                        info.src_mac[0], info.src_mac[1], info.src_mac[2],
                        info.src_mac[3], info.src_mac[4], info.src_mac[5],
                        info.dst_mac[0], info.dst_mac[1], info.dst_mac[2],
                        info.dst_mac[3], info.dst_mac[4], info.dst_mac[5]
                    );

                    trace!("ブロードキャストパケットの詳細: {:02x?}", raw_packet);
                    broadcast_packets.insert(identifier, (now, info));
                    return true;
                }
            }

            let info = PacketInfo {
                ether_type,
                protocol: get_protocol_name(raw_packet).to_string(),
                length: raw_packet.len(),
                first_detection: now,
                src_mac,
                dst_mac,
                detect_count: 1, // 初回検出
            };
            broadcast_packets.insert(identifier, (now, info));
            false
        } else {
            let mut recent_raws = self.raw_packets.lock().await;
            let identifier = RawPacketIdentifier {
                data: raw_packet.to_vec(),
            };

            let now = Instant::now();
            if let Some((last_seen, mut info)) = recent_raws.remove(&identifier) {
                if now.duration_since(last_seen) < Self::DUPLICATE_THRESHOLD {
                    info.detect_count += 1; // カウントを増やす
                    info!(
                        "完全一致パケットを検出（ループの可能性）: 検出回数={}回目 タイプ={:?} プロトコル={} 長さ={} 初回検出からの経過={}ms 送信元MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} 宛先MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        info.detect_count, info.ether_type, info.protocol, info.length,
                        now.duration_since(info.first_detection).as_millis(),
                        info.src_mac[0], info.src_mac[1], info.src_mac[2],
                        info.src_mac[3], info.src_mac[4], info.src_mac[5],
                        info.dst_mac[0], info.dst_mac[1], info.dst_mac[2],
                        info.dst_mac[3], info.dst_mac[4], info.dst_mac[5]
                    );

                    if info.protocol == "TCP" {
                        debug!("TCPパケットの詳細: フラグ={:08b}", raw_packet[47]);
                    }
                    trace!("パケットの詳細: {:02x?}", raw_packet);
                    recent_raws.insert(identifier, (now, info)); // 更新した情報を保存
                    return true;
                }
            }

            let info = PacketInfo {
                ether_type,
                protocol: get_protocol_name(raw_packet).to_string(),
                length: raw_packet.len(),
                first_detection: now,
                src_mac,
                dst_mac,
                detect_count: 1, // 初回検出
            };
            recent_raws.insert(identifier, (now, info));
            false
        }
    }

    pub async fn cleanup_if_needed(&self) {
        let mut last_cleanup = self.last_cleanup.lock().await;
        let now = SystemTime::now();

        if now.duration_since(*last_cleanup).unwrap() >= CLEANUP_INTERVAL {
            let mut recent_raws = self.raw_packets.lock().await;
            let mut broadcast_packets = self.broadcast_packets.lock().await;
            let now_instant = Instant::now();

            let raw_count = recent_raws.len();
            let broadcast_count = broadcast_packets.len();

            // 通常パケットのクリーンアップ
            recent_raws.retain(|_, (last_seen, _)| {
                now_instant.duration_since(*last_seen) < CLEANUP_INTERVAL
            });

            // ブロードキャストパケットのクリーンアップ
            broadcast_packets.retain(|_, (last_seen, _)| {
                now_instant.duration_since(*last_seen) < CLEANUP_INTERVAL
            });

            info!(
                "キャッシュクリーンアップ実行: 通常パケット {}→{}, ブロードキャスト {}→{}",
                raw_count,
                recent_raws.len(),
                broadcast_count,
                broadcast_packets.len()
            );

            *last_cleanup = now;
        }
    }
}

fn extract_mac_addresses(packet: &[u8]) -> ([u8; 6], [u8; 6]) {
    let mut src_mac = [0u8; 6];
    let mut dst_mac = [0u8; 6];

    if packet.len() >= 12 {
        dst_mac.copy_from_slice(&packet[0..6]);
        src_mac.copy_from_slice(&packet[6..12]);
    }

    (src_mac, dst_mac)
}

fn is_broadcast_or_multicast(packet: &[u8]) -> bool {
    if packet.len() < 6 {
        return false;
    }
    packet[0] & 0x01 == 0x01 // 宛先MACの最下位ビットで判断
}

fn get_protocol_name(packet: &[u8]) -> String {
    if packet.len() < 14 + 20 {
        // Ethernet + IP header
        return "Unknown".to_string();
    }

    // IPヘッダのプロトコルフィールド（offset 23）を取得
    let protocol = packet[23];
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        _ => "Other",
    }
    .to_string()
}
