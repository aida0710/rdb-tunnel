use crate::idps_log;
use crate::packet::analysis::ethernet::parse_ethernet_header;
use crate::packet::analysis::firewall::{Filter, FirewallPacket, IpFirewall, Policy};
use crate::packet::analysis::ip::parse_ip_packet;
use crate::packet::types::EtherType;
use crate::packet::{InetAddr, PacketData};
use chrono::Utc;
use lazy_static::lazy_static;
use log::info;
use std::net::IpAddr;

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
        fw.add_rule(Filter::DstIpAddress("192.168.100.168".parse().unwrap()), 98);
        fw.add_rule(Filter::SrcIpAddress("192.168.100.168".parse().unwrap()), 97);
        fw.add_rule(Filter::DstIpAddress("192.168.100.95".parse().unwrap()), 96);
        fw.add_rule(Filter::SrcIpAddress("192.168.100.95".parse().unwrap()), 95);
        fw.add_rule(Filter::DstIpAddress("192.168.100.81".parse().unwrap()), 64);
        fw.add_rule(Filter::SrcIpAddress("192.168.100.81".parse().unwrap()), 63);
        fw.add_rule(Filter::DstPort(5432), 95);
        fw.add_rule(Filter::SrcPort(5432), 90);
        fw.add_rule(Filter::DstPort(2233), 85);
        fw.add_rule(Filter::SrcPort(2233), 80);
        fw.add_rule(Filter::DstPort(19132), 75);
        fw.add_rule(Filter::SrcPort(19132), 70);
        fw.add_rule(Filter::DstPort(19133), 65);
        fw.add_rule(Filter::SrcPort(19133), 60);
        fw.add_rule(Filter::DstPort(1900), 55);
        fw.add_rule(Filter::SrcPort(1900), 50);
        fw
    };
}

pub struct PacketAnalyzer {}

impl PacketAnalyzer {
    pub async fn analyze_packet(ethernet_frame: &[u8]) -> AnalyzeResult {
        // 基本的な長さチェック
        if ethernet_frame.len() < 14 + 20 {
            idps_log!("パケットが短すぎます: パケット長={}、期待値={}", ethernet_frame.len(), 14 + 20);
            return AnalyzeResult::Reject;
        }

        // Ethernetヘッダーの解析
        let ethernet_header = match parse_ethernet_header(ethernet_frame) {
            Ok(result) => result,
            Err(_) => return AnalyzeResult::Reject,
        };

        // IPパケットの解析
        let (src_ip, dst_ip, ip_protocol, src_port, dst_port, flags) = match parse_ip_packet(ethernet_frame, ethernet_header.ether_type).await {
            Ok(result) => result,
            Err(e) => return e,
        };

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

        if ethernet_header.ether_type == EtherType::IP_V6 {
            return AnalyzeResult::Reject;
        }

        info!(
            "Transport: {}:{} -> {}:{}, Flags: SYN={}, ACK={}, RST={}, FIN={}",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            flags & 0x02 != 0, // SYN
            flags & 0x10 != 0, // ACK
            flags & 0x04 != 0, // RST
            flags & 0x01 != 0  // FIN
        );

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
            raw_packet: ethernet_frame.to_vec(),
        })
    }
}
