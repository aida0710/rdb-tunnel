use crate::idps_log;
use crate::packet::analysis::arp_controller::ArpController;
use crate::packet::analysis::ethernet::parse_ethernet_header;
use crate::packet::analysis::firewall::{Filter, FirewallPacket, IpFirewall, Policy};
use crate::packet::analysis::ip::parse_ip_header;
use crate::packet::analysis::transport::parse_transport_header;
use crate::packet::analysis::ttl_handler::TtlHandler;
use crate::packet::types::{EtherType, IpProtocol};
use crate::packet::{InetAddr, PacketData};
use chrono::Utc;
use lazy_static::lazy_static;
use log::{debug, info};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::Mutex;

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
}

lazy_static! {
    static ref FIREWALL: IpFirewall = {
        let mut fw = IpFirewall::new(Policy::Blacklist);
        fw.add_rule(Filter::DstIpAddress("160.251.175.134".parse().unwrap()), 100);
        fw.add_rule(Filter::SrcIpAddress("160.251.175.134".parse().unwrap()), 99);
        fw.add_rule(Filter::DstPort(5432), 95);
        fw.add_rule(Filter::SrcPort(5432), 90);
        fw.add_rule(Filter::DstPort(2233), 85);
        fw.add_rule(Filter::SrcPort(2233), 80);
        fw.add_rule(Filter::DstPort(22), 75);
        fw.add_rule(Filter::SrcPort(22), 70);
        fw
    };
    // TTLハンドラーをグローバルで保持し、状態を維持
    static ref TTL_HANDLER: Mutex<TtlHandler> = Mutex::new(TtlHandler::new(1, 1));
}

pub struct PacketAnalyzer {
    arp_controller: ArpController, // 追加
}

impl PacketAnalyzer {
    pub fn new() -> Self {
        Self {
            arp_controller: ArpController::new(), // 追加
        }
    }

    pub async fn analyze_packet(&self, ethernet_frame: &[u8]) -> AnalyzeResult {
        // 基本的な長さチェック
        if ethernet_frame.len() < 14 + 20 {
            idps_log!("パケットが短すぎます: パケット長={}、期待値={}", ethernet_frame.len(), 14 + 20);
            return AnalyzeResult::Reject;
        }

        // Ethernetヘッダーの解析
        let (ethernet_header, _) = match parse_ethernet_header(ethernet_frame) {
            Some(result) => result,
            None => return AnalyzeResult::Reject,
        };

        // IPパケットの解析
        let (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset) = match Self::parse_ip_packet(ethernet_frame, ethernet_header.ether_type).await {
            Ok(result) => result,
            Err(e) => return e,
        };

        // ARPパケットの制御（追加）
        if ethernet_header.ether_type == EtherType::ARP {
            if !self.arp_controller.should_process(src_ip, dst_ip).await {
                // .awaitを追加
                debug!("ARP制御により破棄: src={}, dst={}", src_ip, dst_ip);
                return AnalyzeResult::Reject;
            }
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
            return AnalyzeResult::Reject;
        }

        // TTL処理（ARPパケット以外）
        if ethernet_header.ether_type != EtherType::ARP {
            let mut frame_copy = ethernet_frame.to_vec();

            let mut ttl_handler = TTL_HANDLER.lock().await;
            if !ttl_handler.process_packet(&mut frame_copy) {
                debug!("パケットループを検出: src={}, dst={}, protocol={:?}", src_ip, dst_ip, ip_protocol);
                return AnalyzeResult::Reject;
            }

            info!("通過パケット: src={}, dst={}, protocol={:?}", src_ip, dst_ip, ip_protocol);

            return AnalyzeResult::Accept(PacketData {
                src_mac: ethernet_header.src_mac,
                dst_mac: ethernet_header.dst_mac,
                ether_type: ethernet_header.ether_type,
                src_ip: InetAddr(src_ip),
                dst_ip: InetAddr(dst_ip),
                src_port: src_port as i32,
                dst_port: dst_port as i32,
                ip_protocol,
                timestamp: Utc::now(),
                data: frame_copy[payload_offset..].to_vec(),
                raw_packet: frame_copy, // 更新されたフレームを使用
            });
        }

        // ARPパケットなど
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
            data: ethernet_frame[payload_offset..].to_vec(),
            raw_packet: ethernet_frame.to_vec(),
        })
    }

    async fn parse_ip_packet(ethernet_frame: &[u8], ether_type: EtherType) -> Result<(IpAddr, IpAddr, IpProtocol, u16, u16, usize), AnalyzeResult> {
        let src_ip;
        let dst_ip;
        let mut src_port = 0u16;
        let mut dst_port = 0u16;
        let mut payload_offset = 14usize;
        let mut ip_protocol = IpProtocol::UNKNOWN;

        // Ethernetヘッダー以降のデータを取得
        let ip_data = &ethernet_frame[14..];

        match ether_type {
            EtherType::IP_V4 | EtherType::IP_V6 => match parse_ip_header(ip_data).await {
                Ok(Some(ip_header)) => {
                    src_ip = ip_header.src_ip;
                    dst_ip = ip_header.dst_ip;
                    ip_protocol = ip_header.ip_protocol;
                    payload_offset = 14 + ip_header.header_length;

                    if !ip_header.ip_protocol.is_icmp() {
                        return Err(AnalyzeResult::Reject);
                    }

                    if let Some((transport_header, _)) = parse_transport_header(ip_data) {
                        src_port = transport_header.src_port;
                        dst_port = transport_header.dst_port;
                    }
                },
                Err(_e) => {
                    idps_log!("IPヘッダーの解析に失敗しました: タイプ={:?}", ether_type);
                    return Err(AnalyzeResult::Reject);
                },
                _ => {
                    idps_log!("IPヘッダーが見つかりませんでした");
                    return Err(AnalyzeResult::Reject);
                },
            },
            EtherType::ARP => {
                if ethernet_frame.len() >= 42 {
                    // ARPパケットの最小長
                    src_ip = IpAddr::V4(Ipv4Addr::new(ethernet_frame[28], ethernet_frame[29], ethernet_frame[30], ethernet_frame[31]));
                    dst_ip = IpAddr::V4(Ipv4Addr::new(ethernet_frame[38], ethernet_frame[39], ethernet_frame[40], ethernet_frame[41]));
                } else {
                    idps_log!("ARPパケットが短すぎます: パケット長={}、期待値=42", ethernet_frame.len());
                    return Err(AnalyzeResult::Reject);
                }
            },
            _ => {
                // arpとicmp以外をすべて排除
                return Err(AnalyzeResult::Reject);
            },
        }

        Ok((src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset))
    }
}
