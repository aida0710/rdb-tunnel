use std::sync::atomic::{AtomicU64, Ordering};
use crate::packet::{PacketData, Protocol};

#[derive(Default)]
pub struct PacketMetrics {
    // パケット統計
    pub total_packets: AtomicU64,
    pub processed_packets: AtomicU64,
    pub dropped_packets: AtomicU64,

    // プロトコル統計
    pub ipv4_packets: AtomicU64,
    pub ipv6_packets: AtomicU64,
    pub arp_packets: AtomicU64,
    pub tcp_packets: AtomicU64,
    pub udp_packets: AtomicU64,
    pub icmp_packets: AtomicU64,

    // エラー統計
    pub parse_errors: AtomicU64,
    pub process_errors: AtomicU64,

    // ファイアウォール統計
    pub allowed_packets: AtomicU64,
    pub blocked_packets: AtomicU64,
}

impl PacketMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_packet(&self, packet_data: &PacketData) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);

        match packet_data.ether_type {
            Protocol::IP_V4 => self.ipv4_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::IP_V6 => self.ipv6_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::ARP => self.arp_packets.fetch_add(1, Ordering::Relaxed),
            _ => {}
        };

        match packet_data.ip_protocol {
            Protocol::TCP => self.tcp_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::UDP => self.udp_packets.fetch_add(1, Ordering::Relaxed),
            Protocol::ICMP | Protocol::ICMP_V6 => self.icmp_packets.fetch_add(1, Ordering::Relaxed),
            _ => {}
        };
    }

    pub fn format_metrics(&self) -> String {
        format!(
            "Packet Statistics:\n\
             Total: {}, Processed: {}, Dropped: {}\n\
             IPv4: {}, IPv6: {}, ARP: {}\n\
             TCP: {}, UDP: {}, ICMP: {}\n\
             Allowed: {}, Blocked: {}\n\
             Errors: Parse={}, Process={}",
            self.total_packets.load(Ordering::Relaxed),
            self.processed_packets.load(Ordering::Relaxed),
            self.dropped_packets.load(Ordering::Relaxed),
            self.ipv4_packets.load(Ordering::Relaxed),
            self.ipv6_packets.load(Ordering::Relaxed),
            self.arp_packets.load(Ordering::Relaxed),
            self.tcp_packets.load(Ordering::Relaxed),
            self.udp_packets.load(Ordering::Relaxed),
            self.icmp_packets.load(Ordering::Relaxed),
            self.allowed_packets.load(Ordering::Relaxed),
            self.blocked_packets.load(Ordering::Relaxed),
            self.parse_errors.load(Ordering::Relaxed),
            self.process_errors.load(Ordering::Relaxed),
        )
    }
}