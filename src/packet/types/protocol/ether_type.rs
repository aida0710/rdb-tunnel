use bytes::BytesMut;
use postgres_types::{IsNull, ToSql, Type};
use std::error::Error;

// EtherType (IEEE 802.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EtherType(u16);

#[allow(dead_code)]
impl EtherType {
    // 既知のEtherType定数
    pub const IP_V4: EtherType = EtherType(0x0800);
    pub const IP_V6: EtherType = EtherType(0x86DD);
    pub const ARP: EtherType = EtherType(0x0806);
    pub const RARP: EtherType = EtherType(0x8035);
    pub const VLAN: EtherType = EtherType(0x8100);
    pub const UNKNOWN: EtherType = EtherType(0);

    pub const fn new(value: u16) -> Self {
        EtherType(value)
    }

    pub fn value(&self) -> u16 {
        self.0
    }

    pub fn as_i32(&self) -> i32 {
        self.0 as i32
    }

    // Ethernetプロトコルかどうかを判定
    pub fn is_ethernet_protocol(&self) -> bool {
        self.0 >= 0x0800
    }
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        EtherType(value)
    }
}

impl ToSql for EtherType {
    fn to_sql(&self, _ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        (self.0 as i32).to_sql(_ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <i32 as ToSql>::accepts(ty)
    }

    fn to_sql_checked(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        (self.0 as i32).to_sql_checked(ty, out)
    }
}
