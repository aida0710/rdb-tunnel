use bytes::BytesMut;
use postgres_types::{IsNull, ToSql, Type};
use std::error::Error;

/// IPプロトコル番号 (IANA)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpProtocol(u8);

#[allow(dead_code)]
impl IpProtocol {
    /// 既知のIPプロトコル定数
    pub const ICMP: IpProtocol = IpProtocol(1);
    pub const TCP: IpProtocol = IpProtocol(6);
    pub const UDP: IpProtocol = IpProtocol(17);
    pub const DNS: IpProtocol = IpProtocol(53);
    pub const ICMP_V6: IpProtocol = IpProtocol(58);
    pub const DHCP: IpProtocol = IpProtocol(67);
    pub const UNKNOWN: IpProtocol = IpProtocol(0);

    pub const fn new(value: u8) -> Self {
        IpProtocol(value)
    }

    pub fn value(&self) -> u8 {
        self.0
    }

    pub fn as_i32(&self) -> i32 {
        self.0 as i32
    }

    /// TCPまたはUDPかどうかを判定
    pub fn is_transport_protocol(&self) -> bool {
        matches!(self.0, 6 | 17) // TCP or UDP
    }

    /// ICMPかどうかを判定
    pub fn is_icmp(&self) -> bool {
        matches!(self.0, 1 | 58) // ICMP or ICMPv6
    }
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        IpProtocol(value)
    }
}

impl ToSql for IpProtocol {
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
