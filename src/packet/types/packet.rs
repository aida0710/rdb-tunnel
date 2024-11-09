use super::{InetAddr, MacAddr};
use crate::packet::types::protocol::{EtherType, IpProtocol};
use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct PacketData {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: EtherType,
    pub src_ip: InetAddr,
    pub dst_ip: InetAddr,
    pub src_port: i32,
    pub dst_port: i32,
    pub ip_protocol: IpProtocol,
    pub timestamp: DateTime<Utc>,
    pub data: Vec<u8>,
    pub raw_packet: Vec<u8>,
}

#[derive(Clone)]
pub struct Packet {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: i32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub ip_protocol: i32,
    pub timestamp: DateTime<Utc>,
    pub data: Vec<u8>,
    pub raw_packet: Vec<u8>,
}

impl PacketData {
    pub fn to_packet(&self) -> Packet {
        Packet {
            src_mac: self.src_mac.clone(),
            dst_mac: self.dst_mac.clone(),
            ether_type: self.ether_type.as_i32(),
            src_ip: self.src_ip.0,
            dst_ip: self.dst_ip.0,
            src_port: Some(self.src_port),
            dst_port: Some(self.dst_port),
            ip_protocol: self.ip_protocol.as_i32(),
            timestamp: self.timestamp,
            data: self.data.clone(),
            raw_packet: self.raw_packet.clone(),
        }
    }
}

impl Packet {
    pub fn to_packet_data(&self) -> PacketData {
        PacketData {
            src_mac: self.src_mac.clone(),
            dst_mac: self.dst_mac.clone(),
            ether_type: EtherType::from(self.ether_type as u16),
            src_ip: InetAddr(self.src_ip),
            dst_ip: InetAddr(self.dst_ip),
            src_port: self.src_port.unwrap_or(0),
            dst_port: self.dst_port.unwrap_or(0),
            ip_protocol: IpProtocol::from(self.ip_protocol as u8),
            timestamp: self.timestamp,
            data: self.data.clone(),
            raw_packet: self.raw_packet.clone(),
        }
    }
}
