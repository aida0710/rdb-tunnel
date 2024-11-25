use crate::packet::reader::error::PacketReaderError;
use crate::packet::Packet;
use log::{debug, error, info, trace};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use crate::idps_log;

pub struct PacketSender;

impl PacketSender {
    const MAX_PACKET_SIZE: usize = 1500;

    pub async fn send_packet(
        interface: &NetworkInterface,
        packet: &Packet,
    ) -> Result<(), PacketReaderError> {
        if packet.raw_packet.len() > Self::MAX_PACKET_SIZE {
            return Err(PacketReaderError::SendError(format!(
                "パケットサイズが制限を超えています: {} bytes (最大: {} bytes)",
                packet.raw_packet.len(),
                Self::MAX_PACKET_SIZE
            )));
        }

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
                trace!(
                    "送信パケット詳細: EtherType: {}, 送信元IP: {}, 宛先IP: {}, 送信元ポート: {}, 宛先ポート: {}, IPプロトコル: {}, タイムスタンプ: {}",
                    packet.ether_type, packet.src_ip, packet.dst_ip,
                    packet.src_port.map_or("未設定".to_string(), |p| p.to_string()),
                    packet.dst_port.map_or("未設定".to_string(), |p| p.to_string()),
                    packet.ip_protocol, packet.timestamp
                );
                Ok(())
            }
            Some(Err(e)) => {
                error!("パケット送信に失敗しました: {}", e);
                Err(PacketReaderError::SendError(e.to_string()))
            }
            None => {
                idps_log!("宛先が指定されていないためスキップ");
                Err(PacketReaderError::SendError(
                    "宛先が指定されていません".to_string(),
                ))
            }
        }
    }
}
