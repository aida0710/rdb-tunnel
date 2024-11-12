use crate::packet::analysis::error::PacketAnalysisError;
use crate::packet::analysis::ethernet::parse_ethernet_header;
use crate::packet::analysis::firewall::{Filter, FirewallPacket, IpFirewall, Policy};
use crate::packet::analysis::ip::parse_ip_header;
use crate::packet::analysis::transport::parse_transport_header;
use crate::packet::types::{EtherType, IpProtocol};
use crate::packet::{InetAddr, PacketData};
use chrono::Utc;
use lazy_static::lazy_static;
use log::{error, trace};
use std::net::{IpAddr, Ipv4Addr};

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

pub struct PacketAnalyzer;

impl PacketAnalyzer {
    pub async fn analyze_packet(ethernet_frame: &[u8]) -> AnalyzeResult {
        if ethernet_frame.len() < 14 {
            error!("ethernet headerが14byte未満です");
            return AnalyzeResult::Reject;
        }

        Self::inner_parse(ethernet_frame, 0).await
    }

    async fn inner_parse(ethernet_frame: &[u8], depth: u8) -> AnalyzeResult {
        if depth > 5 || ethernet_frame.len() < 14 {
            return AnalyzeResult::Reject;
        }

        let (ethernet_header, _remaining_frame) = match parse_ethernet_header(ethernet_frame) {
            Some((header, remaining_frame)) => (header, remaining_frame),
            None => {
                return AnalyzeResult::Error(
                    PacketAnalysisError::InterfaceNotFound("Interface name".to_string())
                );
            }
        };

        let (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset) =
            Self::parse_ip_packet(ethernet_frame, ethernet_header.ether_type).await;

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
