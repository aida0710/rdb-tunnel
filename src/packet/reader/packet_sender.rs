use crate::packet::error::PacketError;
use crate::packet::types::Packet;
use log::{debug, error, trace};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};

pub struct PacketSender;

impl PacketSender {
    const MAX_PACKET_SIZE: usize = 1500;

    pub async fn send_packet(
        interface: &NetworkInterface,
        packet: &Packet,
    ) -> Result<(), PacketError> {
        if packet.raw_packet.len() > Self::MAX_PACKET_SIZE {
            debug!(
                "パケットサイズが大きすぎるためスキップ: {} bytes",
                packet.raw_packet.len()
            );
            return Err(PacketError::PacketSizeTooLarge(packet.raw_packet.len()));
        }

        trace!("パケット送信中: {}: {} {}",
            packet.timestamp,
            packet.src_ip,
            packet.dst_ip
        );

        let (mut tx, _) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                error!("未対応のチャネルタイプです");
                return Err(PacketError::UnsupportedChannelType);
            }
            Err(e) => return Err(PacketError::NetworkError(e.to_string())),
        };

        match tx.send_to(&*packet.raw_packet, None) {
            Some(Ok(_)) => {
                trace!("パケット送信完了: ip-prot:{} {} -> {}",
                    packet.ip_protocol,
                    packet.src_ip,
                    packet.dst_ip,
                );
                Ok(())
            }
            Some(Err(e)) => {
                error!("パケット送信に失敗しました: {}", e);
                Err(PacketError::SendError(e.to_string()))
            }
            None => {
                error!("宛先が指定されていないためスキップ");
                Err(PacketError::SendError("宛先が指定されていません".to_string()))
            }
        }
    }
}