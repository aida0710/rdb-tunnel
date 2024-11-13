use crate::database::{Database, DatabaseError, ExecuteQuery};
use crate::packet::types::PacketData;
use crate::packet::Packet;
use chrono::{DateTime, Utc};
use log::info;
use std::net::IpAddr;
use std::time::Instant;
use tokio_postgres::types::ToSql;

pub struct PacketRepository;

impl PacketRepository {
    const CHUNK_SIZE: usize = 1000;

    pub async fn bulk_insert(packets: Vec<PacketData>) -> Result<(), DatabaseError> {
        if packets.is_empty() {
            return Ok(());
        }

        let db = Database::get_database();
        let start_time = Instant::now();
        let mut processed = 0;

        for chunk in packets.chunks(Self::CHUNK_SIZE) {
            let (query, params) = Self::build_bulk_insert_query(chunk);
            let result = db.execute(&query, &params).await? as usize;
            processed += result;
        }

        info!(
            "{}個のパケットを{}秒で一括挿入しました",
            processed,
            start_time.elapsed().as_secs_f64()
        );

        Ok(())
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
                    i * 11 + 1, i * 11 + 2, i * 11 + 3, i * 11 + 4, i * 11 + 5,
                    i * 11 + 6, i * 11 + 7, i * 11 + 8, i * 11 + 9, i * 11 + 10,
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

    pub async fn get_filtered_packets(
        is_first: bool,
        last_timestamp: Option<&DateTime<Utc>>,
    ) -> Result<Vec<Packet>, DatabaseError> {
        let db = Database::get_database();

        let (query, params): (_, Vec<&(dyn ToSql + Sync)>) = if is_first {
            (
                "SELECT * FROM packets
                WHERE timestamp >= NOW() - INTERVAL '30 seconds'
                ORDER BY timestamp ASC".to_string(),
                vec![]
            )
        } else if let Some(ts) = last_timestamp {
            (
                "SELECT * FROM packets
                WHERE timestamp > $1
                ORDER BY timestamp ASC".to_string(),
                vec![ts]
            )
        } else {
            (
                "SELECT * FROM packets
                WHERE timestamp >= NOW() - INTERVAL '5 seconds'
                ORDER BY timestamp ASC".to_string(),
                vec![]
            )
        };

        let rows = db.query(&query, &params).await?;
        Ok(rows.into_iter().map(|row| Packet {
            src_mac: row.get("src_mac"),
            dst_mac: row.get("dst_mac"),
            ether_type: row.get("ether_type"),
            src_ip: row.get("src_ip"),
            dst_ip: row.get("dst_ip"),
            src_port: row.get("src_port"),
            dst_port: row.get("dst_port"),
            ip_protocol: row.get("ip_protocol"),
            timestamp: row.get("timestamp"),
            data: row.get("data"),
            raw_packet: row.get("raw_packet"),
        }).collect())
    }
}