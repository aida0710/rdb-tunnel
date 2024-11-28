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

        info!("バルク挿入開始: パケット数={}", packets.len());

        let db = Database::get_database();
        let start_time = Instant::now();
        let packets = std::sync::Arc::new(packets);

        for chunk in packets.chunks(Self::CHUNK_SIZE) {
            let mut retries = 0;
            let chunk_data = chunk.to_vec(); // チャンクのコピーを作成
            loop {
                let chunk_clone = chunk_data.clone(); // クロージャ用にクローン
                match db
                    .transaction(|tx| {
                        Box::pin(async move {
                            // メインテーブルへの挿入とIDの取得
                            let (main_query, main_params) = Self::build_main_insert_query(&node_id, &chunk_clone);
                            let rows = tx.query(&main_query, &main_params[..]).await?;

                            // 詳細テーブルへの挿入
                            let (detail_query, detail_params) = Self::build_detail_insert_query(&chunk_clone, &rows);
                            tx.execute(&detail_query, &detail_params[..]).await?;

                            Ok(())
                        })
                    })
                    .await
                {
                    Ok(_) => break,
                    Err(e) if retries < Self::MAX_RETRIES => {
                        log::warn!("チャンクの挿入に失敗（リトライ {}/{}）: {:?}", retries + 1, Self::MAX_RETRIES, e);
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

    fn build_main_insert_query<'a>(node_id: &'a i16, packets: &'a [PacketData]) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(packets.len() * 3);

        for packet in packets {
            params.extend_from_slice(&[node_id, &packet.timestamp, &packet.raw_packet]);
        }

        let placeholders: Vec<String> = (0..packets.len())
            .map(|i| {
                let base = i * 3;
                format!("(${}, ${}, ${})", base + 1, base + 2, base + 3)
            })
            .collect();

        let query = format!(
            "WITH inserted AS (
                INSERT INTO packets (node_id, timestamp, raw_packet)
                VALUES {}
                RETURNING id, timestamp
            )
            SELECT id, timestamp FROM inserted",
            placeholders.join(",")
        );

        info!("メインクエリ: {}", query);
        info!("メインパラメータ数: {}", params.len());

        (query, params)
    }

    fn build_detail_insert_query<'a>(packets: &'a [PacketData], rows: &[tokio_postgres::Row]) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
        info!("詳細テーブル挿入開始: 返却された行数={}", rows.len());
        for (i, row) in rows.iter().enumerate() {
            let id: i64 = row.get("id");
            let timestamp: DateTime<Utc> = row.get("timestamp");
            info!("行 {}: id={}, timestamp={}", i, id, timestamp);
        }

        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(packets.len() * 9);

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
                &packet.data,
            ]);
        }

        let placeholders: Vec<String> = rows
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let id: i64 = row.get("id");
                let timestamp: DateTime<Utc> = row.get("timestamp");
                format!(
                    "({}, TIMESTAMP WITH TIME ZONE '{}' AT TIME ZONE 'UTC', ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    id,
                    timestamp.format("%Y-%m-%d %H:%M:%S%.6f%:z"),
                    i * 9 + 1,
                    i * 9 + 2,
                    i * 9 + 3,
                    i * 9 + 4,
                    i * 9 + 5,
                    i * 9 + 6,
                    i * 9 + 7,
                    i * 9 + 8,
                    i * 9 + 9
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

        info!("詳細クエリ: {}", query);
        info!("詳細パラメータ数: {}", params.len());

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
