use crate::packet::monitor::error::MonitorError;
use crate::packet::writer::PacketWriter;
use log::{error, info, trace};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockType, SockaddrLike, SockaddrStorage};
use pnet::datalink::{self, Channel::Ethernet, Config, NetworkInterface};
use std::os::fd::AsRawFd;
use std::time::Duration;

const READ_BUFFER_SIZE: usize = 65536;
const WRITE_BUFFER_SIZE: usize = 65536;
const READ_TIMEOUT: Duration = Duration::from_secs(1);
const PACKET_OUTGOING: u8 = 4;

pub struct NetworkMonitor;

impl NetworkMonitor {
    pub async fn start(interface: NetworkInterface) -> Result<(), MonitorError> {
        let sock_fd = socket::socket(AddressFamily::Packet, SockType::Raw, SockFlag::empty(), None).map_err(|e| MonitorError::NetworkError(e.to_string()))?;

        let config = Config {
            write_buffer_size: WRITE_BUFFER_SIZE,
            read_buffer_size: READ_BUFFER_SIZE,
            read_timeout: Some(READ_TIMEOUT),
            write_timeout: None,
            channel_type: datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: true,
            socket_fd: Some(sock_fd.as_raw_fd()),
        };

        // pnetのチャネル初期化
        let (_tx, _rx) = match datalink::channel(&interface, config) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(MonitorError::UnsupportedChannelType),
            Err(e) => return Err(MonitorError::NetworkError(e.to_string())),
        };

        let mut buf = vec![0u8; 65536];

        info!("インターフェース {} でパケット受信を開始", interface.name);
        let writer = PacketWriter::default();

        loop {
            match socket::recvfrom::<SockaddrStorage>(sock_fd.as_raw_fd(), &mut buf) {
                Ok((size, Some(addr))) => {
                    unsafe {
                        let sock_addr_ll = addr.as_ptr() as *const libc::sockaddr_ll;

                        trace!("addr: {:?}, sock_addr_ll: {:?}, sll_pkttype: {}", addr, sock_addr_ll, (*sock_addr_ll).sll_pkttype);

                        if !sock_addr_ll.is_null() && (*sock_addr_ll).sll_pkttype == PACKET_OUTGOING {
                            // 自身が送信したパケットはスキップ
                            continue;
                        }
                    }

                    if let Err(e) = writer.process_packet(&buf[..size]).await {
                        error!("パケット処理エラー: {}", e);
                    }
                },
                Ok((_, None)) => continue,
                Err(nix::errno::Errno::EAGAIN) => continue,
                Err(e) => {
                    error!("パケット読み取りエラー: {}", e);
                    break;
                },
            }
        }

        Ok(())
    }
}
