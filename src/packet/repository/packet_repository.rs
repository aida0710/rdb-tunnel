use crate::database::{Database, DatabaseError, ExecuteQuery};
use crate::packet::types::PacketData;
use crate::packet::{InetAddr, MacAddr};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
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

        debug!("バルク挿入開始: パケット数={}, node_id={}", packets.len(), node_id);

        let start_time = Instant::now();
        let packets = std::sync::Arc::new(packets);

        for (chunk_index, chunk) in packets.chunks(Self::CHUNK_SIZE).enumerate() {
            debug!("チャンク処理開始: インデックス={}, サイズ={}", chunk_index, chunk.len());
            let mut retries = 0;
            let chunk_data = chunk.to_vec();

            loop {
                let chunk_clone = chunk_data.clone();
                match Self::insert_chunk(node_id, chunk_clone).await {
                    Ok(_) => {
                        debug!("チャンク{}の挿入成功", chunk_index);
                        break;
                    },
                    Err(e) if retries < Self::MAX_RETRIES => {
                        warn!("チャンク{}の挿入に失敗（リトライ {}/{}）: {:?}", chunk_index, retries + 1, Self::MAX_RETRIES, e);
                        retries += 1;
                        tokio::time::sleep(Duration::from_millis(100 * retries)).await;
                    },
                    Err(e) => {
                        warn!("チャンク{}の挿入が最終的に失敗: {:?}", chunk_index, e);
                        return Err(e);
                    },
                }
            }
        }

        let elapsed = start_time.elapsed();
        info!(
            "{}個のパケットを{}秒で一括挿入しました ({}ms/packet)",
            packets.len(),
            elapsed.as_secs_f64(),
            elapsed.as_millis() as f64 / packets.len() as f64
        );

        Ok(())
    }

    async fn insert_chunk(node_id: i16, packets: Vec<PacketData>) -> Result<(), DatabaseError> {
        let db = Database::get_database();
        let start_time = Instant::now();

        db.transaction(|tx| {
            Box::pin(async move {
                let insert_query = "
                    INSERT INTO packets (
                        node_id, timestamp, src_mac, dst_mac, ether_type, ip_protocol,
                        src_ip, dst_ip, src_port, dst_port, raw_packet
                    )
                    SELECT *
                    FROM (
                        SELECT
                            unnest($1::SMALLINT[]) as node_id,
                            unnest($2::TIMESTAMPTZ[]) as timestamp,
                            unnest($3::macaddr[]) as src_mac,
                            unnest($4::macaddr[]) as dst_mac,
                            unnest($5::INTEGER[]) as ether_type,
                            unnest($6::INTEGER[]) as ip_protocol,
                            unnest($7::inet[]) as src_ip,
                            unnest($8::inet[]) as dst_ip,
                            unnest($9::INTEGER[]) as src_port,
                            unnest($10::INTEGER[]) as dst_port,
                            unnest($11::BYTEA[]) as raw_packet
                    ) t";

                let node_ids: Vec<i16> = vec![node_id; packets.len()];
                let timestamps: Vec<DateTime<Utc>> = packets.iter().map(|p| p.timestamp).collect();
                let src_macs: Vec<MacAddr> = packets.iter().map(|p| p.src_mac.clone()).collect();
                let dst_macs: Vec<MacAddr> = packets.iter().map(|p| p.dst_mac.clone()).collect();
                let ether_types: Vec<i32> = packets.iter().map(|p| p.ether_type.as_i32()).collect();
                let ip_protocols: Vec<i32> = packets.iter().map(|p| p.ip_protocol.as_i32()).collect();
                let src_ips: Vec<InetAddr> = packets.iter().map(|p| p.src_ip.clone()).collect();
                let dst_ips: Vec<InetAddr> = packets.iter().map(|p| p.dst_ip.clone()).collect();
                let src_ports: Vec<i32> = packets.iter().map(|p| p.src_port).collect();
                let dst_ports: Vec<i32> = packets.iter().map(|p| p.dst_port).collect();
                let raw_packets: Vec<Vec<u8>> = packets.iter().map(|p| p.raw_packet.clone()).collect();

                debug!("データ挿入開始: パケット数={}, 最初のタイムスタンプ={:?}", packets.len(), timestamps.first());

                let result = tx
                    .execute(
                        insert_query,
                        &[
                            &node_ids,
                            &timestamps,
                            &src_macs,
                            &dst_macs,
                            &ether_types,
                            &ip_protocols,
                            &src_ips,
                            &dst_ips,
                            &src_ports,
                            &dst_ports,
                            &raw_packets,
                        ],
                    )
                    .await
                    .map_err(|e| {
                        warn!("データ挿入中にエラーが発生: {:?}", e);
                        DatabaseError::QueryExecutionError(e.to_string())
                    })?;

                debug!("データ挿入完了: 挿入数={}, 実行時間={}ms", result, start_time.elapsed().as_millis());

                if result as usize != packets.len() {
                    warn!("期待された挿入数と実際の挿入数が一致しません: expected={}, actual={}", packets.len(), result);
                    return Err(DatabaseError::QueryExecutionError("Inserted row count mismatch".to_string()));
                }

                Ok(())
            })
        })
        .await
    }

    pub async fn get_filtered_packets(node_id: i16, is_first: bool, last_timestamp: Option<&DateTime<Utc>>) -> Result<Vec<Vec<u8>>, DatabaseError> {
        let db = Database::get_database();
        let query = if is_first {
            "SELECT raw_packet FROM packets
            WHERE node_id != $1 AND timestamp >= NOW() - INTERVAL '4 seconds'
            ORDER BY timestamp ASC LIMIT 1000"
        } else {
            "SELECT p.id, p.raw_packet
            FROM packets p
            LEFT JOIN processed_packets pp ON p.id = pp.packet_id AND pp.node_id = $1
            WHERE p.node_id != $1
                AND p.timestamp > $2
                AND pp.packet_id IS NULL
            ORDER BY p.timestamp ASC
            LIMIT 1000"
        };

        let fallback_time = Utc::now() - chrono::Duration::seconds(5);
        let params: Vec<&(dyn ToSql + Sync)> = if is_first {
            vec![&node_id]
        } else {
            vec![&node_id, last_timestamp.unwrap_or(&fallback_time)]
        };

        let rows = db.query(query, &params).await?;

        // パケットIDを記録
        if !is_first && !rows.is_empty() {
            let insert_query = "
            INSERT INTO processed_packets (packet_id, node_id)
            VALUES (unnest($1::bigint[]), $2)
        ";
            let packet_ids: Vec<i64> = rows.iter().map(|row| row.get("id")).collect();
            db.execute(insert_query, &[&packet_ids, &node_id]).await?;
        }

        Ok(rows.into_iter().map(|row| row.get("raw_packet")).collect())
    }
}
