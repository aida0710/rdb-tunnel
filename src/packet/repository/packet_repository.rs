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

        // パケットの内容をログ出力
        for (i, packet) in packets.iter().enumerate() {
            debug!(
                "パケット[{}]: timestamp={}, src_mac={}, dst_mac={}, src_ip={}, dst_ip={}, raw_packet_size={}",
                i,
                packet.timestamp,
                packet.src_mac,
                packet.dst_mac,
                packet.src_ip.0,
                packet.dst_ip.0,
                packet.raw_packet.len()
            );
        }

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
                debug!("トランザクション開始: パケット数={}", packets.len());

                // パケットの挿入
                let insert_packets_query = "
                    INSERT INTO packets (node_id, timestamp, raw_packet)
                    SELECT d.node_id, d.ts, d.raw_packet
                    FROM (
                        SELECT
                            unnest($1::SMALLINT[]) as node_id,
                            unnest($2::TIMESTAMPTZ[]) as ts,
                            unnest($3::BYTEA[]) as raw_packet
                    ) d
                    RETURNING id, timestamp, raw_packet";

                let node_ids: Vec<i16> = vec![node_id; packets.len()];
                let timestamps: Vec<DateTime<Utc>> = packets.iter().map(|p| p.timestamp).collect();
                let raw_packets: Vec<Vec<u8>> = packets.iter().map(|p| p.raw_packet.clone()).collect();

                debug!("パケット挿入クエリ実行: node_ids={:?}, timestamps={:?}", node_ids, timestamps);

                let packet_rows = tx.query(insert_packets_query, &[&node_ids, &timestamps, &raw_packets]).await.map_err(|e| {
                    warn!("パケットの挿入中にエラーが発生: {:?}", e);
                    DatabaseError::QueryExecutionError(e.to_string())
                })?;

                debug!("パケット挿入結果: 行数={}, 実行時間={}ms", packet_rows.len(), start_time.elapsed().as_millis());

                for (i, row) in packet_rows.iter().enumerate() {
                    let id: i64 = row.get(0);
                    let ts: DateTime<Utc> = row.get(1);
                    debug!("挿入されたパケット[{}]: id={}, timestamp={}", i, id, ts);
                }

                // パケット詳細の挿入
                let details_query = "
                    INSERT INTO packet_details
                        (packet_id, timestamp, src_mac, dst_mac, ether_type,
                         src_ip, dst_ip, src_port, dst_port, ip_protocol, data)
                    SELECT
                        p.id,
                        p.timestamp,
                        d.src_mac,
                        d.dst_mac,
                        d.ether_type,
                        d.src_ip,
                        d.dst_ip,
                        d.src_port,
                        d.dst_port,
                        d.ip_protocol,
                        d.data
                    FROM (
                        SELECT
                            unnest($1::BIGINT[]) as id,
                            unnest($2::TIMESTAMPTZ[]) as timestamp
                    ) p
                    CROSS JOIN LATERAL (
                        SELECT
                            unnest($3::macaddr[]) as src_mac,
                            unnest($4::macaddr[]) as dst_mac,
                            unnest($5::INTEGER[]) as ether_type,
                            unnest($6::inet[]) as src_ip,
                            unnest($7::inet[]) as dst_ip,
                            unnest($8::INTEGER[]) as src_port,
                            unnest($9::INTEGER[]) as dst_port,
                            unnest($10::INTEGER[]) as ip_protocol,
                            unnest($11::BYTEA[]) as data
                        LIMIT 1
                    ) d";

                let packet_ids: Vec<i64> = packet_rows.iter().map(|r| r.get(0)).collect();
                let packet_timestamps: Vec<DateTime<Utc>> = packet_rows.iter().map(|r| r.get(1)).collect();

                debug!("詳細データ準備: packet_ids={:?}", packet_ids);

                let src_macs: Vec<MacAddr> = packets.iter().map(|p| p.src_mac.clone()).collect();
                let dst_macs: Vec<MacAddr> = packets.iter().map(|p| p.dst_mac.clone()).collect();
                let ether_types: Vec<i32> = packets.iter().map(|p| p.ether_type.as_i32()).collect();
                let src_ips: Vec<InetAddr> = packets.iter().map(|p| p.src_ip.clone()).collect();
                let dst_ips: Vec<InetAddr> = packets.iter().map(|p| p.dst_ip.clone()).collect();
                let src_ports: Vec<i32> = packets.iter().map(|p| p.src_port).collect();
                let dst_ports: Vec<i32> = packets.iter().map(|p| p.dst_port).collect();
                let ip_protocols: Vec<i32> = packets.iter().map(|p| p.ip_protocol.as_i32()).collect();
                let datas: Vec<Vec<u8>> = packets.iter().map(|p| p.data.clone()).collect();

                let details_result = tx
                    .execute(
                        details_query,
                        &[
                            &packet_ids,
                            &packet_timestamps,
                            &src_macs,
                            &dst_macs,
                            &ether_types,
                            &src_ips,
                            &dst_ips,
                            &src_ports,
                            &dst_ports,
                            &ip_protocols,
                            &datas,
                        ],
                    )
                    .await
                    .map_err(|e| {
                        warn!("詳細データの挿入中にエラーが発生: {:?}", e);
                        DatabaseError::QueryExecutionError(e.to_string())
                    })?;

                debug!("詳細データ挿入結果: 行数={}, 実行時間={}ms", details_result, start_time.elapsed().as_millis());

                if details_result as usize != packets.len() {
                    warn!(
                        "期待された挿入数と実際の挿入数が一致しません: expected={}, actual={}, packet_ids={:?}, timestamps={:?}",
                        packets.len(),
                        details_result,
                        packet_ids,
                        packet_timestamps
                    );
                    return Err(DatabaseError::QueryExecutionError("Inserted row count mismatch".to_string()));
                }

                debug!("トランザクション完了: 合計実行時間={}ms", start_time.elapsed().as_millis());
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
             ORDER BY timestamp DESC LIMIT 1000"
        } else {
            "SELECT raw_packet FROM packets
             WHERE node_id != $1 AND timestamp > $2
             ORDER BY timestamp DESC LIMIT 1000"
        };

        let fallback_time = Utc::now() - chrono::Duration::seconds(5);
        let params: Vec<&(dyn ToSql + Sync)> = if is_first {
            vec![&node_id]
        } else {
            vec![&node_id, last_timestamp.unwrap_or(&fallback_time)]
        };

        let rows = db.query(query, &params).await?;
        debug!(
            "フィルタされたパケットの取得: 行数={}, is_first={}, last_timestamp={:?}",
            rows.len(),
            is_first,
            last_timestamp
        );
        Ok(rows.into_iter().map(|row| row.get("raw_packet")).collect())
    }
}
