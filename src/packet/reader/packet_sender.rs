use crate::packet::reader::error::PacketReaderError;
use crate::packet::Packet;
use log::{debug, info, trace};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};

pub struct PacketSender;

impl PacketSender {
    const MAX_PACKET_SIZE: usize = 1500;

    pub fn send_packet(
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

        let (mut tx) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, _)) => tx,
            Ok(_) => return Err(PacketReaderError::UnsupportedChannelType),
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
            Some(Err(e)) => Err(PacketReaderError::SendError(e.to_string())),
            None => Err(PacketReaderError::SendError(
                "宛先が指定されていません".into(),
            )),
        }
    }
}
