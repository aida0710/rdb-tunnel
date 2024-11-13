use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const MAX_CACHE_SIZE: usize = 10000;
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

impl PacketIdentifier {

    // 新しいパケット識別子を生成します
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, protocol: u8, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

// 最近処理したパケットの識別子をキャッシュし、
// 一定時間内に同じパケットが再度現れた場合に検出
pub struct PacketTracker {
    recent_packets: Arc<Mutex<HashSet<PacketIdentifier>>>,
    last_cleanup: Arc<Mutex<SystemTime>>,
}

impl PacketTracker {
    pub fn new() -> Self {
        Self {
            recent_packets: Arc::new(Mutex::new(HashSet::with_capacity(MAX_CACHE_SIZE))),
            last_cleanup: Arc::new(Mutex::new(SystemTime::now())),
        }
    }

    // 重複していない場合、パケット識別子は自動的にキャッシュに追加
    // キャッシュが最大サイズに達した場合、キャッシュはクリア
    pub async fn is_duplicate(&self, identifier: &PacketIdentifier) -> bool {
        let mut recent_packets = self.recent_packets.lock().await;

        if recent_packets.contains(identifier) {
            return true;
        }

        if recent_packets.len() >= MAX_CACHE_SIZE {
            recent_packets.clear();
        }

        recent_packets.insert(identifier.clone());
        false
    }

    // 必要に応じてキャッシュのクリーンアップを実行
    pub async fn cleanup_if_needed(&self) {
        let mut last_cleanup = self.last_cleanup.lock().await;
        let now = SystemTime::now();

        if now.duration_since(*last_cleanup).unwrap() >= CLEANUP_INTERVAL {
            let mut recent_packets = self.recent_packets.lock().await;
            let current_time = now
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            recent_packets.retain(|packet| {
                current_time - packet.timestamp < CLEANUP_INTERVAL.as_secs()
            });

            *last_cleanup = now;
        }
    }
}