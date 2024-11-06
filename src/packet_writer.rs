use crate::database::database::Database;
use crate::database::error::DbError;
use crate::firewall::{Filter, IpFirewall, Policy};
use crate::firewall_packet::FirewallPacket;
use crate::packet_header::parse_ip_header;
use crate::types::{InetAddr, MacAddr, PacketData, Protocol};
use chrono::Utc;
use lazy_static::lazy_static;
use log::{debug, error, info, trace};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_postgres::types::ToSql;

// パケット統計情報の収集用構造体
#[derive(Debug)]
struct PacketStats {
    total_packets: AtomicU64,
    total_bytes: AtomicU64,
    protocol_counts: Arc<Mutex<HashMap<Protocol, u64>>>,
    port_counts: Arc<Mutex<HashMap<u16, u64>>>,
    last_reset: Arc<Mutex<SystemTime>>,
}

impl PacketStats {
    fn new() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            protocol_counts: Arc::new(Mutex::new(HashMap::new())),
            port_counts: Arc::new(Mutex::new(HashMap::new())),
            last_reset: Arc::new(Mutex::new(SystemTime::now())),
        }
    }

    // 統計情報の更新
    async fn update(&self, protocol: Protocol, size: u64, src_port: u16, dst_port: u16) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(size, Ordering::Relaxed);

        let mut protocol_counts = self.protocol_counts.lock().await;
        *protocol_counts.entry(protocol).or_insert(0) += 1;

        let mut port_counts = self.port_counts.lock().await;
        if src_port > 0 {
            *port_counts.entry(src_port).or_insert(0) += 1;
        }
        if dst_port > 0 {
            *port_counts.entry(dst_port).or_insert(0) += 1;
        }
    }
}

lazy_static! {
    static ref PACKET_BUFFER: Arc<Mutex<Vec<PacketData>>> = Arc::new(Mutex::new(Vec::new()));
    static ref FIREWALL: IpFirewall = {
        let mut fw = IpFirewall::new(Policy::Blacklist);
        fw.add_rule(Filter::IpAddress("160.251.175.134".parse().unwrap()), 100);
        fw.add_rule(Filter::Port(13432), 90);
        fw.add_rule(Filter::Port(2222), 80);
        fw
    };
}

pub async fn start_packet_writer() {
    info!("パケットライターを開始します");
    let mut interval_timer = interval(Duration::from_millis(100));

    loop {
        interval_timer.tick().await;

        let packets = {
            let mut buffer = PACKET_BUFFER.lock().await;
            if buffer.is_empty() {
                continue;
            }
            buffer.drain(..).collect::<Vec<_>>()
        };

        if !packets.is_empty() {
            let start = std::time::Instant::now();
            match process_packets(packets).await {
                Ok(_) => {
                    let duration = start.elapsed();
                    debug!("フラッシュ完了: 処理時間 {}ms", duration.as_millis());
                }
                Err(e) => {
                    error!("パケットバッファのフラッシュに失敗しました: {}", e);
                }
            }
        }
    }
}

async fn process_packets(packets: Vec<PacketData>) -> Result<(), DbError> {
    const CHUNK_SIZE: usize = 1000;

    let db = Database::get_database();
    let mut client = db.pool.get().await?;
    let transaction = client.transaction().await?;

    let mut processed = 0;
    let start_time = std::time::Instant::now();

    for chunk in packets.chunks(CHUNK_SIZE) {
        let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
        for packet in chunk {
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

        let placeholders: Vec<String> = (0..chunk.len())
            .map(|i| {
                format!("(${},${},${},${},${},${},${},${},${},${},${})",
                        i * 11 + 1, i * 11 + 2, i * 11 + 3, i * 11 + 4, i * 11 + 5,
                        i * 11 + 6, i * 11 + 7, i * 11 + 8, i * 11 + 9, i * 11 + 10,
                        i * 11 + 11)
            })
            .collect();

        let query = format!(
            "INSERT INTO packets (
                src_mac, dst_mac, ether_type, src_ip, dst_ip, src_port, dst_port,
                ip_protocol, timestamp, data, raw_packet
            ) VALUES {}",
            placeholders.join(",")
        );

        transaction.execute(&query, &params).await?;
        processed += chunk.len();
    }

    transaction.commit().await?;
    info!("{}個のパケットを{}秒で一括挿入しました",
        processed, start_time.elapsed().as_secs_f64());
    Ok(())
}

// イーサネットパケットの解析
async fn parse_and_analyze_packet(ethernet_packet: &[u8]) -> Result<PacketData, DbError> {
    async fn inner_parse(ethernet_packet: &[u8], depth: u8) -> Result<PacketData, DbError> {
        if depth > 5 || ethernet_packet.len() < 14 {
            return Ok(create_empty_packet_data(ethernet_packet));
        }

        let dst_mac = MacAddr([
            ethernet_packet[0], ethernet_packet[1], ethernet_packet[2],
            ethernet_packet[3], ethernet_packet[4], ethernet_packet[5]
        ]);
        let src_mac = MacAddr([
            ethernet_packet[6], ethernet_packet[7], ethernet_packet[8],
            ethernet_packet[9], ethernet_packet[10], ethernet_packet[11]
        ]);

        let mut src_port: u16 = 0;
        let mut dst_port: u16 = 0;
        let mut src_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let mut dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let mut payload_offset: usize = 14;
        let mut ip_protocol = Protocol::UNKNOWN;

        let ether_type = u16::from_be_bytes([ethernet_packet[12], ethernet_packet[13]]);
        let ether_type_protocol = Protocol::from_u16(ether_type);

        match ether_type {
            0x0800 => { // IPv4
                if ethernet_packet.len() > 23 {
                    if let Some(ip_header) = parse_ip_header(&ethernet_packet[14..]) {
                        src_ip = ip_header.src_ip;
                        dst_ip = ip_header.dst_ip;

                        let ihl = (ethernet_packet[14] & 0x0F) as usize * 4;
                        payload_offset = 14 + ihl;

                        let protocol = ethernet_packet[23];
                        ip_protocol = Protocol::ip(protocol as i32);

                        match protocol {
                            6 | 17 => { // TCP or UDP
                                if ethernet_packet.len() >= payload_offset + 4 {
                                    src_port = u16::from_be_bytes([
                                        ethernet_packet[payload_offset],
                                        ethernet_packet[payload_offset + 1]
                                    ]);
                                    dst_port = u16::from_be_bytes([
                                        ethernet_packet[payload_offset + 2],
                                        ethernet_packet[payload_offset + 3]
                                    ]);

                                    if protocol == 6 && ethernet_packet.len() > payload_offset + 12 {
                                        let tcp_offset = ((ethernet_packet[payload_offset + 12] >> 4) as usize) * 4;
                                        payload_offset += tcp_offset;
                                    } else {
                                        payload_offset += 8;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            0x86DD => { // IPv6
                if ethernet_packet.len() > 54 {
                    if let Some(ip_header) = parse_ip_header(&ethernet_packet[14..]) {
                        src_ip = ip_header.src_ip;
                        dst_ip = ip_header.dst_ip;

                        let next_header = ethernet_packet[20];
                        ip_protocol = Protocol::ip(next_header as i32);
                        payload_offset = 54;

                        match next_header {
                            6 | 17 => { // TCP or UDP
                                if ethernet_packet.len() >= payload_offset + 4 {
                                    src_port = u16::from_be_bytes([
                                        ethernet_packet[payload_offset],
                                        ethernet_packet[payload_offset + 1]
                                    ]);
                                    dst_port = u16::from_be_bytes([
                                        ethernet_packet[payload_offset + 2],
                                        ethernet_packet[payload_offset + 3]
                                    ]);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            0x0806 => { // ARP
                if ethernet_packet.len() >= 28 {
                    let sender_ip_bytes = &ethernet_packet[28..32];
                    let target_ip_bytes = &ethernet_packet[38..42];
                    src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        sender_ip_bytes[0], sender_ip_bytes[1],
                        sender_ip_bytes[2], sender_ip_bytes[3],
                    ));
                    dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        target_ip_bytes[0], target_ip_bytes[1],
                        target_ip_bytes[2], target_ip_bytes[3],
                    ));
                }
            }
            _ => {
                return Ok(create_empty_packet_data(ethernet_packet));
            }
        }

        Ok(PacketData {
            src_mac,
            dst_mac,
            ether_type: ether_type_protocol,
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            ip_protocol,
            timestamp: Utc::now(),
            data: ethernet_packet[payload_offset..].to_vec(),
            raw_packet: ethernet_packet.to_vec(),
        })
    }

    inner_parse(ethernet_packet, 0).await
}

// パケットの書き込みエントリーポイント
pub async fn rdb_tunnel_packet_write(ethernet_packet: &[u8]) -> Result<(), DbError> {
    if ethernet_packet.len() < 14 {
        error!("Invalid ethernet packet length");
        return Ok(());
    }

    match parse_and_analyze_packet(ethernet_packet).await {
        Ok(packet_data) => {
            let firewall_packet = FirewallPacket::new(
                packet_data.src_ip.0,
                packet_data.dst_ip.0,
                packet_data.src_port as u16,
                packet_data.dst_port as u16,
                match packet_data.src_ip.0 {
                    IpAddr::V4(_) => 4,
                    IpAddr::V6(_) => 6,
                },
            );

            if FIREWALL.check(firewall_packet) {
                trace!("許可：firewall_packet: {}:{} -> {}:{}",
                    packet_data.src_ip.0, packet_data.src_port,
                    packet_data.dst_ip.0, packet_data.dst_port
                );

                PACKET_BUFFER.lock().await.push(packet_data);
            } else {
                trace!("不許可：firewall_packet: {}:{} -> {}:{}",
                    packet_data.src_ip.0, packet_data.src_port,
                    packet_data.dst_ip.0, packet_data.dst_port
                );
            }
            Ok(())
        }
        Err(e) => {
            error!("パケット解析エラー: {}", e);
            Err(e)
        }
    }
}

fn create_empty_packet_data(raw_packet: &[u8]) -> PacketData {
    PacketData {
        src_mac: MacAddr([0; 6]),
        dst_mac: MacAddr([0; 6]),
        ether_type: Protocol::UNKNOWN,
        src_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        dst_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        src_port: 0,
        dst_port: 0,
        ip_protocol: Protocol::UNKNOWN,
        timestamp: Utc::now(),
        data: Vec::new(),
        raw_packet: raw_packet.to_vec(),
    }
}