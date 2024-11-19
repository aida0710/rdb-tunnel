use crate::packet::analysis::ip::parse_ip_header;
use crate::packet::types::EtherType;
use log::{info, debug};

pub struct TtlHandler {
    min_ttl: u8,
    ttl_decrease: u8,
}

impl TtlHandler {
    pub fn new(min_ttl: u8, ttl_decrease: u8) -> Self {
        Self {
            min_ttl,
            ttl_decrease,
        }
    }

    pub fn process_packet(&self, ethernet_frame: &mut [u8]) -> bool {
        if ethernet_frame.len() < 14 {
            debug!("パケット長が短すぎます: {} bytes", ethernet_frame.len());
            return false;
        }

        let ether_type = u16::from_be_bytes([ethernet_frame[12], ethernet_frame[13]]);
        match ether_type {
            0x0800 => self.process_ipv4(&mut ethernet_frame[14..]),
            0x86DD => self.process_ipv6(&mut ethernet_frame[14..]),
            other => {
                debug!("非IP パケット: EtherType=0x{:04x}", other);
                true
            }
        }
    }

    fn process_ipv4(&self, ip_packet: &mut [u8]) -> bool {
        if ip_packet.len() < 20 {
            debug!("IPv4パケット長が短すぎます: {} bytes", ip_packet.len());
            return false;
        }

        let packet_length = u16::from_be_bytes([ip_packet[2], ip_packet[3]]);
        let current_ttl = ip_packet[8];
        let old_checksum = u16::from_be_bytes([ip_packet[10], ip_packet[11]]);

        if current_ttl < self.min_ttl {
            info!("TTLが最小値未満です: TTL={}, 最小値={}", current_ttl, self.min_ttl);
            return false;
        }

        // TTLの減算
        let new_ttl = current_ttl.saturating_sub(self.ttl_decrease);
        ip_packet[8] = new_ttl;

        // チェックサム再計算前の値を保存
        let pre_recalc_checksum = u16::from_be_bytes([ip_packet[10], ip_packet[11]]);

        // チェックサムの再計算
        self.recalculate_ipv4_checksum(ip_packet);

        // 新しいチェックサムを取得
        let new_checksum = u16::from_be_bytes([ip_packet[10], ip_packet[11]]);

        info!("IPv4パケット処理: TTL {}→{} (減少量: {}), Checksum 0x{:04x}→0x{:04x}, パケット長 {} bytes",
            current_ttl, new_ttl, self.ttl_decrease, old_checksum, new_checksum, packet_length);

        // 詳細なヘッダー情報をデバッグログに出力
        debug!("IPv4ヘッダー詳細:");
        debug!("  Version/IHL: 0x{:02x}", ip_packet[0]);
        debug!("  ToS: 0x{:02x}", ip_packet[1]);
        debug!("  Total Length: {} bytes", packet_length);
        debug!("  Identification: 0x{:02x}{:02x}", ip_packet[4], ip_packet[5]);
        debug!("  Flags/Fragment Offset: 0x{:02x}{:02x}", ip_packet[6], ip_packet[7]);
        debug!("  Protocol: {}", ip_packet[9]);
        debug!("  Source IP: {}.{}.{}.{}", ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
        debug!("  Destination IP: {}.{}.{}.{}", ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);

        true
    }

    fn process_ipv6(&self, ip_packet: &mut [u8]) -> bool {
        if ip_packet.len() < 40 {
            debug!("IPv6パケット長が短すぎます: {} bytes", ip_packet.len());
            return false;
        }

        let payload_length = u16::from_be_bytes([ip_packet[4], ip_packet[5]]);
        let current_hop_limit = ip_packet[7];

        if current_hop_limit < self.min_ttl {
            info!("Hop limitが最小値未満です: Hop limit={}, 最小値={}", current_hop_limit, self.min_ttl);
            return false;
        }

        let new_hop_limit = current_hop_limit.saturating_sub(self.ttl_decrease);
        ip_packet[7] = new_hop_limit;

        info!("IPv6パケット処理: Hop Limit {}→{} (減少量: {}), パケット長 {} bytes (ペイロード長: {} bytes)",
            current_hop_limit, new_hop_limit, self.ttl_decrease,
            payload_length + 40, payload_length);

        // 詳細なヘッダー情報をデバッグログに出力
        debug!("IPv6ヘッダー詳細:");
        debug!("  Version/Traffic Class: 0x{:02x}{:02x}", ip_packet[0], ip_packet[1]);
        debug!("  Flow Label: 0x{:02x}{:02x}{:02x}", ip_packet[2], ip_packet[3], ip_packet[4]);
        debug!("  Next Header: {}", ip_packet[6]);

        // Source IPv6アドレスの出力
        debug!("  Source IPv6: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            ip_packet[8], ip_packet[9], ip_packet[10], ip_packet[11],
            ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15],
            ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19],
            ip_packet[20], ip_packet[21], ip_packet[22], ip_packet[23]);

        // Destination IPv6アドレスの出力
        debug!("  Destination IPv6: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            ip_packet[24], ip_packet[25], ip_packet[26], ip_packet[27],
            ip_packet[28], ip_packet[29], ip_packet[30], ip_packet[31],
            ip_packet[32], ip_packet[33], ip_packet[34], ip_packet[35],
            ip_packet[36], ip_packet[37], ip_packet[38], ip_packet[39]);

        true
    }

    fn recalculate_ipv4_checksum(&self, ip_header: &mut [u8]) {
        let ihl = (ip_header[0] & 0x0F) as usize * 4;
        if ip_header.len() < ihl {
            return;
        }

        let old_checksum = u16::from_be_bytes([ip_header[10], ip_header[11]]);

        ip_header[10] = 0;
        ip_header[11] = 0;

        let mut sum = 0u32;
        for i in (0..ihl).step_by(2) {
            let word = u16::from_be_bytes([ip_header[i], ip_header[i + 1]]);
            sum += word as u32;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let checksum = !(sum as u16);
        ip_header[10] = (checksum >> 8) as u8;
        ip_header[11] = (checksum & 0xFF) as u8;

        debug!("IPv4チェックサム再計算: 0x{:04x} → 0x{:04x}", old_checksum, checksum);
    }
}