use crate::packet::PacketData;
use lazy_static::lazy_static;
use std::sync::Arc;
use tokio::sync::Mutex;

lazy_static! {
    static ref PACKET_BUFFER: Arc<Mutex<Vec<PacketData>>> = Arc::new(Mutex::new(Vec::new()));
}

pub struct PacketBuffer;

#[allow(dead_code)]
impl PacketBuffer {
    pub async fn push(&self, packet: PacketData) {
        PACKET_BUFFER.lock().await.push(packet);
    }

    pub async fn drain(&self) -> Vec<PacketData> {
        let mut buffer = PACKET_BUFFER.lock().await;
        if buffer.is_empty() {
            return Vec::new();
        }
        buffer.drain(..).collect()
    }

    pub async fn len(&self) -> usize {
        PACKET_BUFFER.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        PACKET_BUFFER.lock().await.is_empty()
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        PacketBuffer
    }
}
