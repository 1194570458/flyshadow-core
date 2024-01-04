use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::context::context::TunnelContext;
use crate::tun::packet::{Packet, Protocol, Version};
use crate::tun::tcp_pipe_context::TcpPipeContext;

/// 处理tun客户端数据
pub async fn handle(tcp_stream: TcpStream, source_addr: String, context: Arc<TunnelContext>) {
    eprintln!("Accept tun client:{}", source_addr);
    let (mut client_reader, client_writer) = tcp_stream.into_split();

    let tcp_pipe_context = TcpPipeContext::new();

    let mut data = [0u8; 4096];
    let mut buf = Vec::<u8>::new();

    loop {
        match client_reader.read(&mut data).await {
            Ok(0) => {
                eprintln!("read end");
                break;
            }
            Ok(n) => {
                buf.append(&mut data[..n].to_vec());
                let data = &buf.to_vec();

                let packet = Packet::from_byte(data);
                if packet.get_total_len() == -1 {
                    continue;
                }
                let mut new_buf = buf.split_off(packet.get_total_len() as usize);
                buf.clear();
                buf.append(&mut new_buf);


                if packet.get_version() == Version::IPV4 {
                    match packet.get_protocol() {
                        Protocol::ICMP => {}
                        Protocol::TCP => {
                            if packet.is_syn() {
                                if let Some(tcp_pipe) = tcp_pipe_context.create_pipe(&packet).await {
                                    let _ = context.tunnel_connect_server(format!("{}:{}", packet.get_target_addr(), packet.get_target_port()), format!(":{}:{}", packet.get_source_addr(), packet.get_source_port())).await;
                                    tcp_pipe.do_syn(&packet);
                                    continue;
                                }
                            }
                        }
                        Protocol::UDP => {}
                        Protocol::Unknown => {}
                    }
                }
            }
            Err(e) => {
                eprintln!("read {} Error: {:}", source_addr, e);
                break;
            }
        }
    }
}


pub(crate) fn print(bytes: &[u8]) {
    for byte in bytes {
        print!("{:02x} ", byte);
    }
    println!();
}