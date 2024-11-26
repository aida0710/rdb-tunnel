use bytes::BytesMut;
use postgres_types::{IsNull, ToSql, Type};
use std::error::Error;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct InetAddr(pub IpAddr);

impl ToSql for InetAddr {
    fn to_sql(&self, _ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        match self.0 {
            IpAddr::V4(addr) => {
                out.extend_from_slice(&[2]); // AF_INET
                out.extend_from_slice(&[32]); // /32
                out.extend_from_slice(&[1]); // is_cidr
                out.extend_from_slice(&[4]); // IPv4 = 4 bytes
                out.extend_from_slice(&addr.octets());
            },
            IpAddr::V6(addr) => {
                out.extend_from_slice(&[3]); // AF_INET6
                out.extend_from_slice(&[128]); // /128
                out.extend_from_slice(&[1]); // is_cidr
                out.extend_from_slice(&[16]); // IPv6 = 16 bytes
                out.extend_from_slice(&addr.octets());
            },
        }
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "inet"
    }

    fn to_sql_checked(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.to_sql(ty, out)
    }
}
