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
    pub raw_packet: Vec<u8>,
}

#[derive(Clone, Debug)]
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
    pub raw_packet: Vec<u8>,
}
