use crate::idps_log;
use crate::packet::analysis::AnalyzeResult;
use log::{error, trace};

// ARP固定値
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_HLEN_ETHERNET: u8 = 6;
const ARP_PLEN_IPV4: u8 = 4;

// ARPパケットの固定サイズ
const ETHERNET_HEADER_SIZE: usize = 14;
const ARP_HEADER_SIZE: usize = 8;
const ARP_ADDRESSES_SIZE: usize = 20;
const MIN_ARP_PACKET_SIZE: usize = ETHERNET_HEADER_SIZE + ARP_HEADER_SIZE + ARP_ADDRESSES_SIZE;

pub async fn parse_arp_packet(ethernet_frame: &[u8]) -> Result<Option<Vec<u8>>, AnalyzeResult> {
    // 基本的なサイズチェック
    if ethernet_frame.len() < MIN_ARP_PACKET_SIZE {
        idps_log!("ARPパケットのサイズが小さすぎます: {} バイト < 必要な {} バイト", ethernet_frame.len(), MIN_ARP_PACKET_SIZE);
        return Err(AnalyzeResult::Reject);
    }

    // ARPペイロードの開始位置を取得
    let payload = &ethernet_frame[ETHERNET_HEADER_SIZE..];

    // ARPヘッダーのチェック
    let hardware_type = u16::from_be_bytes([payload[0], payload[1]]);
    if hardware_type != ARP_HTYPE_ETHERNET {
        idps_log!("ARPハードウェアタイプが無効です: {}", hardware_type);
        return Err(AnalyzeResult::Reject);
    }

    let protocol_type = u16::from_be_bytes([payload[2], payload[3]]);
    if protocol_type != ARP_PTYPE_IPV4 {
        idps_log!("ARPプロトコルタイプが無効です: {}", protocol_type);
        return Err(AnalyzeResult::Reject);
    }

    let hardware_len = payload[4];
    if hardware_len != ARP_HLEN_ETHERNET {
        idps_log!("ARPハードウェア長が無効です: {}", hardware_len);
        return Err(AnalyzeResult::Reject);
    }

    let protocol_len = payload[5];
    if protocol_len != ARP_PLEN_IPV4 {
        idps_log!("ARPプロトコル長が無効です: {}", protocol_len);
        return Err(AnalyzeResult::Reject);
    }

    let mut frame = ethernet_frame.to_vec();
    validate_and_mark_padding(&mut frame)?;

    Ok(Some(frame))
}

fn validate_and_mark_padding(frame: &mut Vec<u8>) -> Result<(), AnalyzeResult> {
    if frame.len() <= MIN_ARP_PACKET_SIZE {
        return Ok(());
    }

    let padding_start = MIN_ARP_PACKET_SIZE;
    let padding_marker = frame[padding_start];

    if padding_marker != 0x00 && padding_marker != 0x01 {
        error!("パディングマーカーが無効です: {}", padding_marker);
        return Err(AnalyzeResult::Reject);
    }

    if padding_marker == 0x01 {
        trace!("パディングが既にマークされています");
        return Err(AnalyzeResult::Reject);
    }

    trace!("ethernet frame(Before editing): {:?}", frame);

    // 残りのパディングが0x00であることを確認
    for (i, &byte) in frame.iter().enumerate().skip(padding_start + 1) {
        if byte != 0x00 {
            idps_log!("パディング内容が無効です: インデックス {}, 値 {}", i, byte);
            return Err(AnalyzeResult::Reject);
        }
    }

    // パディングマーカーを設定
    frame[padding_start] = 0x01;

    trace!("ethernet frame(After editing): {:?}", frame);

    Ok(())
}
