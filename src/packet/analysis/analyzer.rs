use crate::packet::analysis::ethernet::parse_ethernet_header;
use crate::packet::analysis::firewall::{Filter, FirewallPacket, IpFirewall, Policy};
use crate::packet::analysis::ip::parse_ip_header;
use crate::packet::analysis::transport::parse_transport_header;
use crate::packet::types::{EtherType, IpProtocol};
use crate::packet::{InetAddr, PacketData};
use chrono::Utc;
use lazy_static::lazy_static;
use log::{debug, trace};
use std::net::{IpAddr, Ipv4Addr};
use crate::packet::analysis::duplicate_tracker::{PacketIdentifier, PacketTracker};
use crate::packet::analysis::error::PacketAnalysisError;
use crate::packet::analysis::ttl_processor::TtlProcessor;

#[derive(Clone, Copy)]
pub struct IpHeader {
    pub version: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

pub enum AnalyzeResult {
    Accept(PacketData),
    Reject,
    Error(PacketAnalysisError),
}

lazy_static! {
    static ref FIREWALL: IpFirewall = {
        let mut fw = IpFirewall::new(Policy::Blacklist);
        fw.add_rule(Filter::DstIpAddress("160.251.175.134".parse().unwrap()), 100);
        fw.add_rule(Filter::DstPort(5432), 95);
        fw.add_rule(Filter::SrcPort(5432), 90);
        fw.add_rule(Filter::DstPort(2222), 85);
        fw.add_rule(Filter::SrcPort(2222), 80);
        fw
    };
}

pub struct PacketAnalyzer {
    tracker: PacketTracker,
    ttl_processor: TtlProcessor,
}

impl PacketAnalyzer {
    pub fn new() -> Self {
        Self {
            tracker: PacketTracker::new(),
            ttl_processor: TtlProcessor::new(),
        }
    }

    pub async fn analyze_packet(&self, ethernet_frame: &[u8]) -> AnalyzeResult {
        // 基本的な長さチェック
        if ethernet_frame.len() < 14 + 20 {  // Ethernet + 最小IP header
            return AnalyzeResult::Reject;
        }

        // Ethernetヘッダーの解析
        let (ethernet_header, _) = match parse_ethernet_header(ethernet_frame) {
            Some(result) => result,
            None => return AnalyzeResult::Reject,
        };

        // IPヘッダーの解析とTTLチェック
        let ip_header_offset = 14;
        let ttl = ethernet_frame[ip_header_offset + 8];

        if !self.ttl_processor.is_valid_ttl(ttl) {
            trace!("TTLが低すぎるパケットを破棄: TTL={}", ttl);
            return AnalyzeResult::Reject;
        }

        // IPパケットの詳細な解析
        let (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset) =
            Self::parse_ip_packet(ethernet_frame, ethernet_header.ether_type).await;

        // 重複チェック
        let identifier = PacketIdentifier::new(src_ip, dst_ip, ip_protocol.value(), src_port, dst_port);
        if self.tracker.is_duplicate(&identifier).await {
            trace!("重複パケットを検出: src={}:{}, dst={}:{}",
                src_ip, src_port, dst_ip, dst_port);
            return AnalyzeResult::Reject;
        }

        // Firewallチェック
        let firewall_packet = FirewallPacket::from_packet(
            ethernet_header.src_mac.clone(),
            ethernet_header.dst_mac.clone(),
            ethernet_header.ether_type,
            src_ip,
            dst_ip,
            ip_protocol,
            src_port,
            dst_port,
        );

        if !FIREWALL.check(&firewall_packet) {
            trace!("Firewallによりバッファ追加が禁止: {}:{} -> {}:{}",
                firewall_packet.src_ip, firewall_packet.src_port,
                firewall_packet.dst_ip, firewall_packet.dst_port
            );
            return AnalyzeResult::Reject;
        }

        // キャッシュのクリーンアップ
        self.tracker.cleanup_if_needed().await;

        // 新しいパケットの作成（TTLを減少させる）
        let mut new_packet = ethernet_frame.to_vec();
        self.ttl_processor.process_packet(&mut new_packet, ip_header_offset);

        debug!("パケット処理完了: TTL={} -> {}", ttl, ttl - 1);

        AnalyzeResult::Accept(PacketData {
            src_mac: ethernet_header.src_mac,
            dst_mac: ethernet_header.dst_mac,
            ether_type: ethernet_header.ether_type,
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            ip_protocol,
            timestamp: Utc::now(),
            data: new_packet[payload_offset..].to_vec(),
            raw_packet: new_packet,
        })
    }

    async fn parse_ip_packet(
        ethernet_frame: &[u8],
        ether_type: EtherType,
    ) -> (IpAddr, IpAddr, IpProtocol, u16, u16, usize) {
        let mut src_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let mut dst_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        let mut src_port = 0u16;
        let mut dst_port = 0u16;
        let mut payload_offset = 14usize;
        let mut ip_protocol = IpProtocol::UNKNOWN;

        // Ethernetヘッダー以降のデータを取得
        let ip_data = &ethernet_frame[14..];

        match ether_type {
            EtherType::IP_V4 | EtherType::IP_V6 => {
                if let Some(ip_header) = parse_ip_header(ip_data).await {
                    src_ip = ip_header.src_ip;
                    dst_ip = ip_header.dst_ip;
                    ip_protocol = ip_header.ip_protocol;
                    payload_offset = 14 + ip_header.header_length;

                    if let Some((transport_header, _)) = parse_transport_header(ip_data) {
                        src_port = transport_header.src_port;
                        dst_port = transport_header.dst_port;
                    }
                }
            }
            EtherType::ARP => {
                if ethernet_frame.len() >= 42 { // ARPパケットの最小長
                    src_ip = IpAddr::V4(Ipv4Addr::new(
                        ethernet_frame[28], ethernet_frame[29],
                        ethernet_frame[30], ethernet_frame[31],
                    ));
                    dst_ip = IpAddr::V4(Ipv4Addr::new(
                        ethernet_frame[38], ethernet_frame[39],
                        ethernet_frame[40], ethernet_frame[41],
                    ));
                }
            }
            _ => {}
        }

        (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset)
    }
}
