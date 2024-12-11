use crate::idps_log;
use crate::packet::analysis::AnalyzeResult;

#[derive(Debug)]
pub struct TransportHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}

pub fn parse_transport_header(data: &[u8]) -> Result<TransportHeader, AnalyzeResult> {
    // IPヘッダが必要なので、最低でもIPヘッダ長以上のデータが必要
    if data.len() < 20 {
        idps_log!("IPヘッダが必要なので、最低でもIPヘッダ長以上のデータが必要の為、捨てられました");
        return Err(AnalyzeResult::Reject);
    }

    // IPヘッダ長を取得
    let ihl = ((data[0] & 0xF) * 4) as usize;

    // トランスポートヘッダの開始位置を計算
    let transport_data = &data[ihl..];

    // トランスポートヘッダには少なくとも4バイト必要
    if transport_data.len() < 4 {
        idps_log!("トランスポートヘッダが4byte未満の為、捨てられました");
        return Err(AnalyzeResult::Reject);
    }

    let header = TransportHeader {
        src_port: u16::from_be_bytes([transport_data[0], transport_data[1]]),
        dst_port: u16::from_be_bytes([transport_data[2], transport_data[3]]),
        flags: transport_data[12],
    };

    Ok(header)
}
