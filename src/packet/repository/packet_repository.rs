use crate::database::{Database, DatabaseError, ExecuteQuery};
use crate::packet::types::PacketData;
use crate::packet::Packet;
use chrono::{DateTime, Utc};
use log::info;
use std::time::{Duration, Instant};
use tokio_postgres::types::ToSql;

pub struct PacketRepository;

impl PacketRepository {
    const CHUNK_SIZE: usize = 150;
    const MAX_RETRIES: u64 = 3;

    pub async fn bulk_insert(packets: Vec<PacketData>) -> Result<(), DatabaseError> {
        if packets.is_empty() {
            return Ok(());
        }

        let db = Database::get_database();
        let start_time = Instant::now();
        let processed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let packets = std::sync::Arc::new(packets);

        let processed_clone = processed.clone();
        let packets_clone = packets;

        db.transaction(|tx| {
            let processed = processed_clone;
            let packets = packets_clone;

            Box::pin(async move {
                for (chunk_idx, chunk) in packets.chunks(Self::CHUNK_SIZE).enumerate() {
                    let mut retries = 0;
                    loop {
                        let (query, params) = Self::build_bulk_insert_query(chunk);
                        match tx.execute(&query, &params[..]).await {
                            Ok(count) => {
                                processed.fetch_add(count as usize, std::sync::atomic::Ordering::SeqCst);
                                break;
                            },
                            Err(e) if retries < Self::MAX_RETRIES => {
                                log::warn!("チャンク {}の挿入に失敗（リトライ {}/{}）: {:?}", chunk_idx, retries + 1, Self::MAX_RETRIES, e);
                                retries += 1;
                                tokio::time::sleep(Duration::from_millis(100 * retries)).await;
                            },
                            Err(e) => return Err(DatabaseError::QueryExecutionError(e.to_string())),
                        }
                    }
                }

                info!(
                    "{}個のパケットを{}秒で一括挿入しました",
                    processed.load(std::sync::atomic::Ordering::SeqCst),
                    start_time.elapsed().as_secs_f64()
                );

                Ok(())
            })
        })
        .await
    }

    fn build_bulk_insert_query(packets: &[PacketData]) -> (String, Vec<&(dyn ToSql + Sync)>) {
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(packets.len() * 11);

        for packet in packets {
            params.extend_from_slice(&[
                &packet.src_mac,
                &packet.dst_mac,
                &packet.ether_type,
                &packet.src_ip,
                &packet.dst_ip,
                &packet.src_port,
                &packet.dst_port,
                &packet.ip_protocol,
                &packet.timestamp,
                &packet.data,
                &packet.raw_packet,
            ]);
        }

        let placeholders: Vec<String> = (0..packets.len())
            .map(|i| {
                format!(
                    "(${},${},${},${},${},${},${},${},${},${},${})",
                    i * 11 + 1,
                    i * 11 + 2,
                    i * 11 + 3,
                    i * 11 + 4,
                    i * 11 + 5,
                    i * 11 + 6,
                    i * 11 + 7,
                    i * 11 + 8,
                    i * 11 + 9,
                    i * 11 + 10,
                    i * 11 + 11
                )
            })
            .collect();

        let query = format!(
            "INSERT INTO packets (
                src_mac, dst_mac, ether_type, src_ip, dst_ip, src_port, dst_port,
                ip_protocol, timestamp, data, raw_packet
            ) VALUES {}",
            placeholders.join(",")
        );

        (query, params)
    }

    pub async fn get_filtered_packets(is_first: bool, last_timestamp: Option<&DateTime<Utc>>) -> Result<Vec<Vec<u8>>, DatabaseError> {
        let db = Database::get_database();
        let query = if is_first {
            "SELECT raw_packet FROM packets WHERE timestamp >= NOW() - INTERVAL '4 seconds' ORDER BY timestamp ASC LIMIT 1000"
        } else {
            "SELECT raw_packet FROM packets WHERE timestamp > $1 ORDER BY timestamp ASC LIMIT 1000"
        };

        let fallback_time = Utc::now() - chrono::Duration::seconds(5);
        let params: Vec<&(dyn ToSql + Sync)> = if is_first { vec![] } else { vec![last_timestamp.unwrap_or(&fallback_time)] };

        let rows = db.query(query, &params).await?;
        Ok(rows.into_iter().map(|row| row.get("raw_packet")).collect())
    }
}
