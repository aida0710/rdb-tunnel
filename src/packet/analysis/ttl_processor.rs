pub struct TtlProcessor {
    max_ttl: u8,
}

impl TtlProcessor {
    pub fn new() -> Self {
        Self {
            max_ttl: 64,
        }
    }

    pub fn is_valid_ttl(&self, ttl: u8) -> bool {
        ttl > 1 && ttl <= self.max_ttl
    }

    pub fn process_packet(&self, packet: &mut [u8], ip_header_offset: usize) {
        // TTLを減少
        packet[ip_header_offset + 8] = packet[ip_header_offset + 8] - 1;

        // チェックサムの再計算
        self.update_ipv4_checksum(&mut packet[ip_header_offset..]);
    }

    fn update_ipv4_checksum(&self, ip_header: &mut [u8]) {
        // チェックサムフィールドをクリア
        ip_header[10] = 0;
        ip_header[11] = 0;

        // チェックサムの計算
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += ((ip_header[i] as u32) << 8) | ip_header[i + 1] as u32;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let checksum = !sum as u16;

        // 新しいチェックサムを設定
        ip_header[10] = (checksum >> 8) as u8;
        ip_header[11] = (checksum & 0xFF) as u8;
    }
}