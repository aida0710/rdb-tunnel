use bytes::BytesMut;
use log::error;
use postgres_types::{FromSql, IsNull, ToSql, Type};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mac_string = self.0.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
        write!(f, "{}", mac_string)
    }
}

impl ToSql for MacAddr {
    fn to_sql(&self, _ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        out.extend_from_slice(&self.0);
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "macaddr"
    }

    fn to_sql_checked(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.to_sql(ty, out)
    }
}

impl<'a> FromSql<'a> for MacAddr {
    fn from_sql(_ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        if raw.len() != 6 {
            error!("MACアドレスの長さが不正です");
            return Err("Invalid MAC address length".into());
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(raw);
        Ok(MacAddr(addr))
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "macaddr"
    }
}
