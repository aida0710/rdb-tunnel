use crate::idps_log;
use crate::packet::types::{EtherType, MacAddr};
use log::debug;

#[derive(Debug)]
pub struct EthernetHeader {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: EtherType,
}

pub fn parse_ethernet_header(frame: &[u8]) -> Option<(EthernetHeader, &[u8])> {
    if frame.len() < 14 {
        idps_log!("Ethernet header too short");
        return None;
    }

    let (src_mac, dst_mac) = extract_mac_addresses(frame);
    let ether_type = parse_ether_type(frame);

    debug!("Ethernet: {} -> {} (Type: {:?})",
        src_mac, dst_mac, ether_type);

    Some((
        EthernetHeader {
            src_mac,
            dst_mac,
            ether_type,
        },
        &frame[14..],
    ))
}

fn extract_mac_addresses(frame: &[u8]) -> (MacAddr, MacAddr) {
    let dst_mac = MacAddr([frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]]);
    let src_mac = MacAddr([frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]]);
    (src_mac, dst_mac)
}

fn parse_ether_type(frame: &[u8]) -> EtherType {
    let type_value = u16::from_be_bytes([frame[12], frame[13]]);
    EtherType::from(type_value)
}
