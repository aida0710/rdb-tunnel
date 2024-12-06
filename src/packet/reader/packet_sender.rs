use crate::packet::reader::error::PacketReaderError;
use crate::utils::measure_time::measure_time_async;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};

pub struct PacketSender;

impl PacketSender {
    const MAX_PACKET_SIZE: usize = 1500;

    pub async fn send_packet(interface: &NetworkInterface, raw_packet: Vec<u8>) -> Result<(), PacketReaderError> {
        measure_time_async("send packets", true, async {
            if raw_packet.len() > Self::MAX_PACKET_SIZE {
                return Err(PacketReaderError::SendError(format!(
                    "パケットサイズが制限を超えています: {} bytes (最大: {} bytes)",
                    raw_packet.len(),
                    Self::MAX_PACKET_SIZE
                )));
            }

            let mut tx = match datalink::channel(interface, Default::default()) {
                Ok(Ethernet(tx, _)) => tx,
                Ok(_) => return Err(PacketReaderError::UnsupportedChannelType),
                Err(e) => return Err(PacketReaderError::NetworkError(e.to_string())),
            };

            match tx.send_to(&*raw_packet, None) {
                Some(Ok(_)) => Ok(()),
                Some(Err(e)) => Err(PacketReaderError::SendError(e.to_string())),
                None => Err(PacketReaderError::SendError("宛先が指定されていません".into())),
            }
        })
        .await
    }
}
