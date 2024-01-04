use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use crate::context::context::TunnelContext;
use crate::tun::packet::{Packet, Protocol, Version};

/// 处理tun客户端数据
pub async fn handle(tcp_stream: TcpStream, source_addr: String, context: Arc<TunnelContext>) {
    eprintln!("Accept tun client:{}", source_addr);

    let (mut client_reader, client_writer) = tcp_stream.into_split();


    let mut buffer = [0u8; 70000];

    loop {
        match client_reader.read(&mut buffer).await {
            Ok(0) => {
                eprintln!("read end");
                break;
            }
            Ok(n) => {
                let data = &buffer[..n];

                let packet = Packet::from_byte(data);
                if packet.get_version() == Version::IPV4 && (packet.get_protocol() == Protocol::TCP){
                    print(data);
                    println!("{:?}", packet.get_version());
                    println!("{}", packet.get_ip_header_len());
                    println!("{:?}", packet.get_protocol());
                    println!("{}", packet.get_source_addr());
                    println!("{}", packet.get_target_addr());
                    println!("{}", packet.get_source_port());
                    println!("{}", packet.get_target_port());
                }

            }
            Err(e) => {
                eprintln!("read {} Error: {:}", source_addr, e);
                break;
            }
        }
    }
}


pub(crate) fn print(bytes:&[u8]){
    for byte in bytes {
        print!("{:02x} ", byte);
    }
    println!();
}