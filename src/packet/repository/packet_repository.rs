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

        debug!("バルク挿入開始: パケット数={}", packets.len());
        let start_time = Instant::now();
        let packets = std::sync::Arc::new(packets);

        for chunk in packets.chunks(Self::CHUNK_SIZE) {
            let mut retries = 0;
            let chunk_data = chunk.to_vec();

            loop {
                let chunk_clone = chunk_data.clone();
                match Self::insert_chunk(node_id, chunk_clone).await {
                    Ok(_) => break,
                    Err(e) if retries < Self::MAX_RETRIES => {
                        warn!("チャンク挿入に失敗（リトライ {}/{}）: {:?}", retries + 1, Self::MAX_RETRIES, e);
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

    async fn insert_chunk(node_id: i16, packets: Vec<PacketData>) -> Result<(), DatabaseError> {
        let db = Database::get_database();

        db.transaction(|tx| {
            Box::pin(async move {
                let packet_insert_query = "INSERT INTO packets (node_id, timestamp, raw_packet)
                    SELECT * FROM UNNEST($1::SMALLINT[], $2::TIMESTAMPTZ[], $3::BYTEA[])
                    RETURNING id, timestamp";

                let node_ids: Vec<i16> = vec![node_id; packets.len()];
                let timestamps: Vec<DateTime<Utc>> = packets.iter().map(|p| p.timestamp).collect();
                let raw_packets: Vec<Vec<u8>> = packets.iter().map(|p| p.raw_packet.clone()).collect();

                let packet_rows = tx.query(packet_insert_query, &[&node_ids, &timestamps, &raw_packets]).await.map_err(|e| DatabaseError::QueryExecutionError(e.to_string()))?;

                let details_insert_query = "INSERT INTO packet_details
                    (packet_id, timestamp, src_mac, dst_mac, ether_type,
                     src_ip, dst_ip, src_port, dst_port, ip_protocol, data)
                    SELECT
                        p.id, p.timestamp,
                        UNNEST($1::macaddr[]), UNNEST($2::macaddr[]), UNNEST($3::INTEGER[]),
                        UNNEST($4::inet[]), UNNEST($5::inet[]), UNNEST($6::INTEGER[]),
                        UNNEST($7::INTEGER[]), UNNEST($8::INTEGER[]), UNNEST($9::BYTEA[])
                    FROM UNNEST($10::BIGINT[], $11::TIMESTAMPTZ[]) AS p(id, timestamp)";

                let packet_ids: Vec<i64> = packet_rows.iter().map(|r| r.get(0)).collect();
                let packet_timestamps: Vec<DateTime<Utc>> = packet_rows.iter().map(|r| r.get(1)).collect();

                let src_macs: Vec<MacAddr> = packets.iter().map(|p| p.src_mac.clone()).collect();
                let dst_macs: Vec<MacAddr> = packets.iter().map(|p| p.dst_mac.clone()).collect();
                let ether_types: Vec<i32> = packets.iter().map(|p| p.ether_type.as_i32()).collect();
                let src_ips: Vec<InetAddr> = packets.iter().map(|p| p.src_ip.clone()).collect();
                let dst_ips: Vec<InetAddr> = packets.iter().map(|p| p.dst_ip.clone()).collect();
                let src_ports: Vec<i32> = packets.iter().map(|p| p.src_port).collect();
                let dst_ports: Vec<i32> = packets.iter().map(|p| p.dst_port).collect();
                let ip_protocols: Vec<i32> = packets.iter().map(|p| p.ip_protocol.as_i32()).collect();
                let datas: Vec<Vec<u8>> = packets.iter().map(|p| p.data.clone()).collect();

                tx.execute(
                    details_insert_query,
                    &[
                        &src_macs,
                        &dst_macs,
                        &ether_types,
                        &src_ips,
                        &dst_ips,
                        &src_ports,
                        &dst_ports,
                        &ip_protocols,
                        &datas,
                        &packet_ids,
                        &packet_timestamps,
                    ],
                )
                .await
                .map_err(|e| DatabaseError::QueryExecutionError(e.to_string()))?;

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
        Ok(rows.into_iter().map(|row| row.get("raw_packet")).collect())
    }
}
