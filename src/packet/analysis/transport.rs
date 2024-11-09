use log::debug;

#[derive(Debug)]
pub struct TransportHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

pub fn parse_transport_header(data: &[u8]) -> Option<(TransportHeader, &[u8])> {
    // IPヘッダが必要なので、最低でもIPヘッダ長以上のデータが必要
    if data.len() < 20 {
        return None;
    }

    // IPヘッダ長を取得
    let ihl = ((data[0] & 0xF) * 4) as usize;

    // トランスポートヘッダの開始位置を計算
    let transport_data = &data[ihl..];

    // トランスポートヘッダには少なくとも4バイト必要
    if transport_data.len() < 4 {
        return None;
    }

    let header = TransportHeader {
        src_port: u16::from_be_bytes([transport_data[0], transport_data[1]]),
        dst_port: u16::from_be_bytes([transport_data[2], transport_data[3]]),
    };

    debug!("Transport: {} -> {}", header.src_port, header.dst_port);

    Some((header, &transport_data[4..]))
}
