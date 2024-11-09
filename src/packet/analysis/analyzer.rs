use crate::packet::analysis::error::PacketAnalysisError;
use crate::packet::analysis::ethernet::parse_ethernet_header;
use crate::packet::analysis::ip::parse_ip_header;
use crate::packet::analysis::transport::parse_transport_header;
use crate::packet::types::{EtherType, IpProtocol};
use crate::packet::{InetAddr, MacAddr, PacketData};
use chrono::Utc;
use log::error;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy)]
pub struct IpHeader {
    pub version: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

pub struct PacketAnalyzer;

impl PacketAnalyzer {
    pub async fn analyze_packet(ethernet_frame: &[u8]) -> Result<PacketData, PacketAnalysisError> {
        if ethernet_frame.len() < 14 {
            error!("ethernet headerが14byte未満です");
            return Ok(Self::create_empty_packet_data(ethernet_frame));
        }

        Self::inner_parse(ethernet_frame, 0).await
    }

    async fn inner_parse(ethernet_frame: &[u8], depth: u8) -> Result<PacketData, PacketAnalysisError> {
        if depth > 5 || ethernet_frame.len() < 14 {
            return Ok(Self::create_empty_packet_data(ethernet_frame));
        }

        let (ethernet_header, _remaining_frame) = match parse_ethernet_header(ethernet_frame) {
            Some((header, remaining_frame)) => (header, remaining_frame),
            None => {
                eprintln!("{}", PacketAnalysisError::InterfaceNotFound("Interface name".to_string()));
                std::process::exit(1);
            }
        };

        println!("ether_type: {:?}", ethernet_header.ether_type);

        let (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset) =
            Self::parse_ip_packet(ethernet_frame, ethernet_header.ether_type).await;

        Ok(PacketData {
            src_mac,
            dst_mac,
            ether_type,
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port,
            dst_port,
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

        match ether_type {
            EtherType::IP_V4 | EtherType::IP_V6 => {
                if let Some((ip_header)) = parse_ip_header(ethernet_frame).await {
                    let Some((transport_header, _remaining_frame)) = parse_transport_header(ethernet_frame);
                    src_ip = ip_header.src_ip;
                    dst_ip = ip_header.dst_ip;
                    ip_protocol = ip_header.ip_protocol;
                    src_port = transport_header.src_port;
                    dst_port = transport_header.dst_port;
                    payload_offset = ip_header.header_length;
                }
            }
            EtherType::ARP => {
                if ethernet_frame.len() >= 28 {
                    src_ip = IpAddr::V4(Ipv4Addr::new(ethernet_frame[28], ethernet_frame[29], ethernet_frame[30], ethernet_frame[31]));
                    dst_ip = IpAddr::V4(Ipv4Addr::new(ethernet_frame[38], ethernet_frame[39], ethernet_frame[40], ethernet_frame[41]));
                }
            }
            EtherType::RARP => {}
            EtherType::VLAN => {}
            _ => {}
        }

        (src_ip, dst_ip, ip_protocol, src_port, dst_port, payload_offset)
    }

    fn create_empty_packet_data(raw_packet: &[u8]) -> PacketData {
        PacketData {
            src_mac: MacAddr([0; 6]),
            dst_mac: MacAddr([0; 6]),
            ether_type: EtherType::UNKNOWN,
            src_ip: InetAddr(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            dst_ip: InetAddr(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            src_port: 0,
            dst_port: 0,
            ip_protocol: IpProtocol::UNKNOWN,
            timestamp: Utc::now(),
            data: Vec::new(),
            raw_packet: raw_packet.to_vec(),
        }
    }
}
