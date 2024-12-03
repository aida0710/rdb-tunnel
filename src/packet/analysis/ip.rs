use crate::idps_log;
use crate::packet::analysis::transport::parse_transport_header;
use crate::packet::analysis::AnalyzeResult;
use crate::packet::types::{EtherType, IpProtocol};
use rtnetlink::IpVersion;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct IpHeader {
    pub version: IpVersion,
    pub ip_protocol: IpProtocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub header_length: usize,
}

pub async fn parse_ip_packet(ethernet_frame: &[u8], ether_type: EtherType) -> Result<(IpAddr, IpAddr, IpProtocol, u16, u16), AnalyzeResult> {
    let src_ip;
    let dst_ip;
    let mut src_port = 0;
    let mut dst_port = 0;
    let ip_protocol;

    // Ethernetヘッダー以降のデータを取得
    let ip_data = &ethernet_frame[14..];

    match ether_type {
        EtherType::IP_V4 | EtherType::IP_V6 => match parse_ip_header(ip_data).await {
            Ok(Some(ip_header)) => {
                src_ip = ip_header.src_ip;
                dst_ip = ip_header.dst_ip;
                ip_protocol = ip_header.ip_protocol;

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
        _ => {
            src_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
            dst_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
            ip_protocol = IpProtocol::UNKNOWN;
        },
    }

    Ok((src_ip, dst_ip, ip_protocol, src_port, dst_port))
}

async fn parse_ip_header(data: &[u8]) -> Result<Option<IpHeader>, AnalyzeResult> {
    let version = (data[0] >> 4) & 0xF;
    match version {
        4 => {
            if data.len() < 20 {
                // 最小IPv4ヘッダ長
                idps_log!("IPv4ヘッダが短すぎます: {} バイト < 最小値20バイト", data.len());
                return Err(AnalyzeResult::Reject);
            }

            let ihl = (data[0] & 0xF) as usize * 4; // IPヘッダ長
            if data.len() < ihl {
                idps_log!("IPv4パケット長がヘッダ長より短いです: {} バイト < 宣言値 {} バイト", data.len(), ihl);
                return Err(AnalyzeResult::Reject);
            }

            let ip_protocol = IpProtocol::from(data[9]); // プロトコルフィールド
            let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
            let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

            Ok(Some(IpHeader {
                version: IpVersion::V4,
                ip_protocol,
                src_ip: IpAddr::V4(src_ip),
                dst_ip: IpAddr::V4(dst_ip),
                header_length: ihl,
            }))
        },
        6 => {
            // IPv6ヘッダは40バイト固定
            if data.len() < 40 {
                idps_log!("IPv6ヘッダが短すぎます: {} バイト < 必要な40バイト", data.len());
                return Err(AnalyzeResult::Reject);
            }

            let ip_protocol = IpProtocol::from(data[6]); // Next Header
            let src_ip = Ipv6Addr::new(
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
                u16::from_be_bytes([data[20], data[21]]),
                u16::from_be_bytes([data[22], data[23]]),
            );
            let dst_ip = Ipv6Addr::new(
                u16::from_be_bytes([data[24], data[25]]),
                u16::from_be_bytes([data[26], data[27]]),
                u16::from_be_bytes([data[28], data[29]]),
                u16::from_be_bytes([data[30], data[31]]),
                u16::from_be_bytes([data[32], data[33]]),
                u16::from_be_bytes([data[34], data[35]]),
                u16::from_be_bytes([data[36], data[37]]),
                u16::from_be_bytes([data[38], data[39]]),
            );

            Ok(Some(IpHeader {
                version: IpVersion::V6,
                ip_protocol,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                header_length: 40,
            }))
        },
        _ => {
            idps_log!("不正なIPバージョンです: {}", version);
            Err(AnalyzeResult::Reject)
        },
    }
}
