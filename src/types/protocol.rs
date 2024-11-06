use bytes::BytesMut;
use postgres_types::{IsNull, ToSql, Type};
use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Protocol(i32);

// イーサネットプロトコル用の実装
impl Protocol {
    // EtherType Constants (IEEE 802.3)
    pub const fn ethernet(value: i32) -> Self {
        Protocol(value)
    }

    // 頻繁に使用される EtherType
    pub const IP_V4: Protocol = Protocol::ethernet(0x0800);
    pub const IP_V6: Protocol = Protocol::ethernet(0x86DD);
    pub const ARP: Protocol = Protocol::ethernet(0x0806);
    pub const RARP: Protocol = Protocol::ethernet(0x8035);
    pub const VLAN: Protocol = Protocol::ethernet(0x8100);
}

// IPプロトコル用の実装
impl Protocol {
    // IP Protocol Numbers (IANA)
    pub const fn ip(value: i32) -> Self {
        Protocol(value)
    }

    // 頻繁に使用されるIPプロトコル
    pub const ICMP: Protocol = Protocol::ip(1);
    pub const TCP: Protocol = Protocol::ip(6);
    pub const UDP: Protocol = Protocol::ip(17);
    pub const DNS: Protocol = Protocol::ip(53);
    pub const ICMP_V6: Protocol = Protocol::ip(58);
    pub const DHCP: Protocol = Protocol::ip(67);
}

// その他のユーティリティ実装
impl Protocol {
    pub const UNKNOWN: Protocol = Protocol(0);

    pub fn from_u16(value: u16) -> Self {
        Protocol(value as i32)
    }

    pub fn from_u8(value: u8) -> Self {
        Protocol(value as i32)
    }

    pub fn as_i32(&self) -> i32 {
        self.0
    }

    pub fn is_ethernet(&self) -> bool {
        self.0 >= 0x0800
    }

    pub fn is_ip(&self) -> bool {
        self.0 > 0 && self.0 < 0x0800
    }
}

impl ToSql for Protocol {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.0.to_sql(_ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <i32 as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.0.to_sql_checked(ty, out)
    }
}
