use crate::database::DbError;
use crate::packet::{InetAddr, MacAddr, PacketData, Protocol};
use crate::packet_header::parse_ip_header;
use chrono::Utc;
use std::net::IpAddr;

pub struct PacketAnalyzer;

impl PacketAnalyzer {
    pub async fn analyze_packet(ethernet_packet: &[u8]) -> Result<PacketData, DbError> {
        if ethernet_packet.len() < 14 {
            return Ok(Self::create_empty_packet_data(ethernet_packet));
        }

        Self::inner_parse(ethernet_packet, 0).await
    }

    async fn inner_parse(ethernet_packet: &[u8], depth: u8) -> Result<PacketData, DbError> {
        if depth > 5 || ethernet_packet.len() < 14 {
            return Ok(Self::create_empty_packet_data(ethernet_packet));
        }

        let (src_mac, dst_mac) = Self::extract_mac_addresses(ethernet_packet);
        let ether_type = u16::from_be_bytes([ethernet_packet[12], ethernet_packet[13]]);
        let ether_type_protocol = Protocol::from_u16(ether_type);

        let (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset) =
            Self::parse_network_layer(ethernet_packet, ether_type).await;

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

    fn extract_mac_addresses(packet: &[u8]) -> (MacAddr, MacAddr) {
        let dst_mac = MacAddr([
            packet[0], packet[1], packet[2],
            packet[3], packet[4], packet[5]
        ]);
        let src_mac = MacAddr([
            packet[6], packet[7], packet[8],
            packet[9], packet[10], packet[11]
        ]);
        (src_mac, dst_mac)
    }

    async fn parse_network_layer(
        packet: &[u8],
        ether_type: u16,
    ) -> (IpAddr, IpAddr, Protocol, u16, u16, usize) {
        let mut src_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let mut dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let mut src_port = 0u16;
        let mut dst_port = 0u16;
        let mut payload_offset = 14usize;
        let mut ip_protocol = Protocol::UNKNOWN;

        match ether_type {
            0x0800 => { // IPv4
                if let Some((header_info, ports)) = Self::parse_ipv4(packet).await {
                    src_ip = header_info.0;
                    dst_ip = header_info.1;
                    ip_protocol = header_info.2;
                    src_port = ports.0;
                    dst_port = ports.1;
                    payload_offset = header_info.3;
                }
            }
            0x86DD => { // IPv6
                if let Some((header_info, ports)) = Self::parse_ipv6(packet).await {
                    src_ip = header_info.0;
                    dst_ip = header_info.1;
                    ip_protocol = header_info.2;
                    src_port = ports.0;
                    dst_port = ports.1;
                    payload_offset = header_info.3;
                }
            }
            0x0806 => { // ARP
                if packet.len() >= 28 {
                    let (src, dst) = Self::parse_arp(packet);
                    src_ip = src;
                    dst_ip = dst;
                }
            }
            _ => {}
        }

        (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset)
    }

    async fn parse_ipv4(packet: &[u8]) -> Option<((IpAddr, IpAddr, Protocol, usize), (u16, u16))> {
        if packet.len() <= 23 {
            return None;
        }

        if let Some(ip_header) = parse_ip_header(&packet[14..]) {
            let ihl = (packet[14] & 0x0F) as usize * 4;
            let payload_offset = 14 + ihl;
            let protocol = packet[23];
            let ip_protocol = Protocol::ip(protocol as i32);

            let mut src_port = 0;
            let mut dst_port = 0;

            if (protocol == 6 || protocol == 17) && packet.len() >= payload_offset + 4 {
                let (s_port, d_port) = Self::extract_ports(packet, payload_offset);
                src_port = s_port;
                dst_port = d_port;
            }

            Some((
                (ip_header.src_ip, ip_header.dst_ip, ip_protocol, payload_offset),
                (src_port, dst_port)
            ))
        } else {
            None
        }
    }

    async fn parse_ipv6(packet: &[u8]) -> Option<((IpAddr, IpAddr, Protocol, usize), (u16, u16))> {
        if packet.len() <= 54 {
            return None;
        }

        if let Some(ip_header) = parse_ip_header(&packet[14..]) {
            let next_header = packet[20];
            let ip_protocol = Protocol::ip(next_header as i32);
            let payload_offset = 54;

            let mut src_port = 0;
            let mut dst_port = 0;

            if (next_header == 6 || next_header == 17) && packet.len() >= payload_offset + 4 {
                let (s_port, d_port) = Self::extract_ports(packet, payload_offset);
                src_port = s_port;
                dst_port = d_port;
            }

            Some((
                (ip_header.src_ip, ip_header.dst_ip, ip_protocol, payload_offset),
                (src_port, dst_port)
            ))
        } else {
            None
        }
    }

    fn parse_arp(packet: &[u8]) -> (IpAddr, IpAddr) {
        let sender_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            packet[28], packet[29], packet[30], packet[31],
        ));
        let target_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            packet[38], packet[39], packet[40], packet[41],
        ));
        (sender_ip, target_ip)
    }

    fn extract_ports(packet: &[u8], offset: usize) -> (u16, u16) {
        let src_port = u16::from_be_bytes([
            packet[offset],
            packet[offset + 1]
        ]);
        let dst_port = u16::from_be_bytes([
            packet[offset + 2],
            packet[offset + 3]
        ]);
        (src_port, dst_port)
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
}
