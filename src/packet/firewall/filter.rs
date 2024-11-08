use crate::packet::MacAddr;
use std::net::IpAddr;

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Filter {
    // L2 Filters
    SrcMacAddress(MacAddr),
    DstMacAddress(MacAddr),
    EtherType(u16),

    // L3 Filters
    SrcIpAddress(IpAddr),
    DstIpAddress(IpAddr),
    IPProtocol(u8),

    // L4 Filters
    SrcPort(u16),
    DstPort(u16),
}