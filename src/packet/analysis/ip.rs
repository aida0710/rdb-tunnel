use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use rtnetlink::IpVersion;
use crate::packet::types::IpProtocol;

#[derive(Debug)]
pub struct IpHeader {
    pub version: IpVersion,
    pub ip_protocol: IpProtocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub header_length: usize,
}

pub async fn parse_ip_header(data: &[u8]) -> Option<IpHeader> {
    let version = (data[0] >> 4) & 0xF;
    match version {
        4 => {
            let ip_protocol_v4 = IpProtocol::from((data[0] & 0xF) << 4);
            let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
            let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

            Some(IpHeader {
                version: IpVersion::V4,
                ip_protocol: ip_protocol_v4,
                src_ip: IpAddr::V4(src_ip),
                dst_ip: IpAddr::V4(dst_ip),
                header_length: data.len(),
            })
        }
        6 => {
            let ip_protocol_v6 = IpProtocol::from(data[6]);
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

            Some(IpHeader {
                version: IpVersion::V6,
                ip_protocol: ip_protocol_v6,
                src_ip: IpAddr::V6(src_ip),
                dst_ip: IpAddr::V6(dst_ip),
                header_length: data.len(),
            })
        }
        _ => None,
    }
}