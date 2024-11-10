use crate::packet::MacAddr;
use std::net::IpAddr;

#[derive(Debug)]
pub struct FirewallPacket {
    // L2 fields
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: u16,

    // L3 fields
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub ip_version: u8,
    pub ip_protocol: u8,

    // L4 fields
    pub src_port: u16,
    pub dst_port: u16,
}

impl FirewallPacket {
    pub fn from_packet(packet: &crate::packet::Packet) -> Self {
        Self {
            src_mac: packet.src_mac.clone(),
            dst_mac: packet.dst_mac.clone(),
            ether_type: packet.ether_type as u16,
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            ip_version: match packet.src_ip {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 6,
            },
            ip_protocol: packet.ip_protocol as u8,
            src_port: packet.src_port.unwrap_or(0) as u16,
            dst_port: packet.dst_port.unwrap_or(0) as u16,
        }
    }
}