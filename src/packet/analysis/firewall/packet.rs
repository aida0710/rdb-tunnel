use crate::packet::types::{EtherType, IpProtocol};
use crate::packet::MacAddr;
use std::net::IpAddr;

#[derive(Debug)]
pub struct FirewallPacket {
    // L2 fields
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: EtherType,

    // L3 fields
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ip_version: u8,
    pub ip_protocol: IpProtocol,

    // L4 fields
    pub src_port: u16,
    pub dst_port: u16,
}

impl FirewallPacket {
    pub fn from_packet(src_mac: MacAddr, dst_mac: MacAddr, ether_type: EtherType, src_ip: IpAddr, dst_ip: IpAddr, ip_protocol: IpProtocol, src_port: u16, dst_port: u16) -> Self {
        Self {
            src_mac,
            dst_mac,
            ether_type,
            src_ip,
            dst_ip,
            ip_version: match src_ip {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 6,
            },
            ip_protocol,
            src_port,
            dst_port,
        }
    }
}
