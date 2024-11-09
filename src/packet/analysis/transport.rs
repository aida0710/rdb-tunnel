use log::debug;

#[derive(Debug)]
pub struct TransportHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

pub fn parse_transport_header(data: &[u8]) -> Option<(TransportHeader, &[u8])> {
    if data.len() < 4 {
        return None;
    }

    let header = TransportHeader {
        src_port: u16::from_be_bytes([data[0], data[1]]),
        dst_port: u16::from_be_bytes([data[2], data[3]]),
    };

    debug!("Transport: {} -> {}", header.src_port, header.dst_port);

    Some((header, &data[4..]))
}
