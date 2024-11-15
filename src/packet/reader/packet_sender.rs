use crate::packet::reader::error::PacketReaderError;
use crate::packet::Packet;
use log::{debug, error, trace};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};

pub struct PacketSender;

impl PacketSender {
    const MAX_PACKET_SIZE: usize = 1500;

    pub async fn send_packet(
        interface: &NetworkInterface,
        packet: &Packet,
    ) -> Result<(), PacketReaderError> {
        if packet.raw_packet.len() > Self::MAX_PACKET_SIZE {
            debug!(
                "パケットサイズが大きすぎるためスキップ: {} bytes",
                packet.raw_packet.len()
            );
            return Err(PacketReaderError::SendError(format!(
                "パケットサイズが制限を超えています: {} bytes (最大: {} bytes)",
                packet.raw_packet.len(),
                Self::MAX_PACKET_SIZE
            )));
        }

        trace!(
            "パケット送信中: {}: {} {}",
            packet.timestamp,
            packet.src_ip,
            packet.dst_ip
        );

        let (mut tx, _) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                error!("未対応のチャネルタイプです");
                return Err(PacketReaderError::UnsupportedChannelType);
            }
            Err(e) => return Err(PacketReaderError::NetworkError(e.to_string())),
        };

        match tx.send_to(&*packet.raw_packet, None) {
            Some(Ok(_)) => {
                trace!("パケット送信完了: {:?}", packet);
                Ok(())
            }
            Some(Err(e)) => {
                error!("パケット送信に失敗しました: {}", e);
                Err(PacketReaderError::SendError(e.to_string()))
            }
            None => {
                error!("宛先が指定されていないためスキップ");
                Err(PacketReaderError::SendError(
                    "宛先が指定されていません".to_string(),
                ))
            }
        }
    }
}
