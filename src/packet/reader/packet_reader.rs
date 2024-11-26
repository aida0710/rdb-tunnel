use crate::packet::reader::error::PacketReaderError;
use crate::packet::reader::packet_sender::PacketSender;
use crate::packet::repository::PacketRepository;
use crate::packet::Packet;
use log::{debug, error, info, trace};
use pnet::datalink::NetworkInterface;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use futures::future::join_all;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct PacketReader {}

use tokio::runtime::Runtime;

impl PacketReader {
    pub async fn start(interface: NetworkInterface) -> Result<(), PacketReaderError> {

        while let Ok(packets) = PacketRepository::get_filtered_packets(false, None).await {
            let sends = packets.into_iter().map(|packet| {
                let interface_clone = interface.clone();
                tokio::spawn(async move {
                    if let Err(e) = PacketSender::send_packet(&interface_clone, &packet) {
                        error!("パケットの送信に失敗しました: {:?}", e);
                    }
                })
            });

            join_all(sends).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }
}
