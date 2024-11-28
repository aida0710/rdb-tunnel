use crate::database::{Database, DatabaseError, ExecuteQuery};
use crate::packet::types::PacketData;
use chrono::{DateTime, Utc};
use log::info;
use std::time::{Duration, Instant};
use tokio_postgres::types::ToSql;

pub struct PacketRepository;

impl PacketRepository {
    const CHUNK_SIZE: usize = 50;
    const MAX_RETRIES: u64 = 3;

    pub async fn bulk_insert(node_id: i16, packets: Vec<PacketData>) -> Result<(), DatabaseError> {
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
                        // メインテーブルへの挿入
                        let (main_query, main_params) = Self::build_main_insert_query(&node_id, chunk);
                        match tx.execute(&main_query, &main_params[..]).await {
                            Ok(count) => {
                                // 詳細テーブルへの挿入
                                let (detail_query, detail_params) = Self::build_detail_insert_query(chunk);
                                match tx.execute(&detail_query, &detail_params[..]).await {
                                    Ok(_) => {
                                        processed.fetch_add(count as usize, std::sync::atomic::Ordering::SeqCst);
                                        break;
                                    },
                                    Err(e) if retries < Self::MAX_RETRIES => {
                                        log::warn!("詳細チャンク {}の挿入に失敗（リトライ {}/{}）: {:?}", chunk_idx, retries + 1, Self::MAX_RETRIES, e);
                                        retries += 1;
                                        tokio::time::sleep(Duration::from_millis(100 * retries)).await;
                                        continue;
                                    },
                                    Err(e) => return Err(DatabaseError::QueryExecutionError(e.to_string())),
                                }
                            },
                            Err(e) if retries < Self::MAX_RETRIES => {
                                log::warn!("メインチャンク {}の挿入に失敗（リトライ {}/{}）: {:?}", chunk_idx, retries + 1, Self::MAX_RETRIES, e);
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

    fn build_main_insert_query<'a>(node_id: &'a i16, packets: &'a [PacketData]) -> (String, Vec<&'a (dyn ToSql + Sync + 'a)>) {
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(packets.len() * 3);

        for packet in packets {
            params.extend_from_slice(&[
                node_id, // 各レコードごとにnode_idを追加
                &packet.timestamp,
                &packet.raw_packet,
            ]);
        }

        let placeholders: Vec<String> = (0..packets.len())
            .map(|i| {
                let base = i * 3;
                format!("(${}, ${}, ${})", base + 1, base + 2, base + 3)
            })
            .collect();

        let query = format!("INSERT INTO packets (node_id, timestamp, raw_packet) VALUES {} RETURNING id", placeholders.join(","));

        (query, params)
    }

    fn build_detail_insert_query(packets: &[PacketData]) -> (String, Vec<&(dyn ToSql + Sync)>) {
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(packets.len() * 10); // 9から10に変更（timestampを追加）

        for packet in packets {
            params.extend_from_slice(&[
                &packet.timestamp, // タイムスタンプを追加
                &packet.src_mac,
                &packet.dst_mac,
                &packet.ether_type,
                &packet.src_ip,
                &packet.dst_ip,
                &packet.src_port,
                &packet.dst_port,
                &packet.ip_protocol,
                &packet.data,
            ]);
        }

        let placeholders: Vec<String> = (0..packets.len())
            .map(|i| {
                format!(
                    "(currval('packets_id_seq') - {} + 1, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    packets.len() - i - 1,
                    i * 10 + 1,
                    i * 10 + 2,
                    i * 10 + 3,
                    i * 10 + 4,
                    i * 10 + 5,
                    i * 10 + 6,
                    i * 10 + 7,
                    i * 10 + 8,
                    i * 10 + 9,
                    i * 10 + 10
                )
            })
            .collect();

        let query = format!(
            "INSERT INTO packet_details (
            packet_id, timestamp, src_mac, dst_mac, ether_type, src_ip, dst_ip,
            src_port, dst_port, ip_protocol, data
        ) VALUES {}",
            placeholders.join(",")
        );

        (query, params)
    }

    pub async fn get_filtered_packets(node_id: i16, is_first: bool, last_timestamp: Option<&DateTime<Utc>>) -> Result<Vec<Vec<u8>>, DatabaseError> {
        let db = Database::get_database();
        let query = if is_first {
            "SELECT raw_packet FROM packets WHERE node_id != $1 AND timestamp >= NOW() - INTERVAL '4 seconds' ORDER BY timestamp DESC LIMIT 1000"
        } else {
            "SELECT raw_packet FROM packets WHERE node_id != $1 AND timestamp > $2 ORDER BY timestamp DESC LIMIT 1000"
        };

        let fallback_time = Utc::now() - chrono::Duration::seconds(5);
        let params: Vec<&(dyn ToSql + Sync)> = if is_first {
            vec![&node_id]
        } else {
            vec![&node_id, last_timestamp.unwrap_or(&fallback_time)]
        };

        let rows = db.query(query, &params).await?;
        Ok(rows.into_iter().map(|row| row.get("raw_packet")).collect())
    }
}
