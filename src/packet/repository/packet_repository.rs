use crate::database::{Database, DatabaseError, ExecuteQuery};
use crate::packet::types::PacketData;
use chrono::{DateTime, Utc};
use log::{debug, info};
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

        debug!("バルク挿入開始: パケット数={}", packets.len());

        let db = Database::get_database();
        let start_time = Instant::now();
        let packets = std::sync::Arc::new(packets);

        for chunk in packets.chunks(Self::CHUNK_SIZE) {
            let mut retries = 0;
            let chunk_data = chunk.to_vec();
            loop {
                let chunk_clone = chunk_data.clone();
                match db
                    .transaction(|tx| {
                        Box::pin(async move {
                            let (query, params) = Self::build_insert_query(&node_id, &chunk_clone);
                            tx.execute(&query, &params[..]).await?;
                            Ok(())
                        })
                    })
                    .await
                {
                    Ok(_) => break,
                    Err(e) if retries < Self::MAX_RETRIES => {
                        log::warn!("チャンク挿入に失敗（リトライ {}/{}）: {:?}", retries + 1, Self::MAX_RETRIES, e);
                        retries += 1;
                        tokio::time::sleep(Duration::from_millis(100 * retries)).await;
                    },
                    Err(e) => return Err(e),
                }
            }
        }

        info!("{}個のパケットを{}秒で一括挿入しました", packets.len(), start_time.elapsed().as_secs_f64());

        Ok(())
    }

    fn build_insert_query<'a>(node_id: &'a i16, packets: &'a [PacketData]) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(packets.len() * 12);

        for packet in packets {
            params.extend_from_slice(&[
                node_id,
                &packet.timestamp,
                &packet.raw_packet,
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

        let with_clauses: Vec<String> = (0..packets.len())
            .map(|i| {
                let base = i * 12;
                format!(
                    "packet_{} AS (
                    INSERT INTO packets (node_id, timestamp, raw_packet)
                    VALUES (${}, ${}, ${})
                    RETURNING id, timestamp
                ),
                packet_details_{} AS (
                    INSERT INTO packet_details (
                        packet_id, timestamp, src_mac, dst_mac, ether_type,
                        src_ip, dst_ip, src_port, dst_port, ip_protocol, data
                    )
                    SELECT
                        id, timestamp, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}
                    FROM packet_{}
                    RETURNING 1
                )",
                    i,
                    base + 1,
                    base + 2,
                    base + 3,
                    i,
                    base + 4,
                    base + 5,
                    base + 6,
                    base + 7,
                    base + 8,
                    base + 9,
                    base + 10,
                    base + 11,
                    base + 12,
                    i
                )
            })
            .collect();

        let query = format!(
            "WITH {}
        SELECT 1",
            with_clauses.join(",\n")
        );

        debug!("結合クエリ: {}", query);
        debug!("パラメータ数: {}", params.len());

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
