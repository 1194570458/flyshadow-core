use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::channel;

use crate::context::context::TunnelContext;
use crate::tun::packet::{Packet, Protocol, Version};
use crate::tun::tcp_pipe_context::TcpPipeContext;
use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

/// 处理tun客户端数据
pub async fn handle(tcp_stream: TcpStream, source_addr: String, context: Arc<TunnelContext>) {
    eprintln!("Accept tun client:{}", source_addr);
    let (mut client_reader, mut client_writer) = tcp_stream.into_split();
    let (sender, mut receiver) = channel::<Vec<u8>>(10);

    spawn(async move {
        while let Some(vec) = receiver.recv().await {
            eprintln!("write to tun client:{}", vec.len());
            print(vec.as_slice());
            if let Err(e) = client_writer.write_all(vec.as_slice()).await {
                eprintln!("Write Tun Client Err:{}", e);
                receiver.close();
                return;
            } else {
                let _ = client_writer.flush().await;
            }
        };
    });

    let tcp_pipe_context = Arc::new(TcpPipeContext::new());

    let mut data = [0u8; 8192];
    let mut buf = Vec::<u8>::new();

    let sender1 = sender.clone();
    let tcp_pipe_context1 = tcp_pipe_context.clone();
    loop {
        match client_reader.read(&mut data).await {
            Ok(0) => {
                eprintln!("read end");
                break;
            }
            Ok(n) => {
                buf.append(&mut data[..n].to_vec());

                'lo: loop {
                    if buf.len() == 0 {
                        break 'lo;
                    }
                    let data = buf.clone();
                    let data_len = data.len();

                    let mut packet = Packet::from_byte(data);
                    let packet_len = packet.get_total_len();
                    if packet_len == -1 || data_len < packet_len as usize {
                        break 'lo;
                    }
                    let mut new_buf = buf.split_off(packet_len as usize);
                    buf.clear();
                    buf.append(&mut new_buf);


                    if packet.get_version() == Version::IPV4 {
                        eprintln!("read client data: ");
                        print(packet.to_byte().as_slice());
                        match packet.get_protocol() {
                            Protocol::ICMP => {}
                            Protocol::TCP => {
                                // 握手
                                if packet.is_syn() {
                                    eprintln!("packet syn ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                                    if let Some(tcp_pipe) = tcp_pipe_context1.create_pipe(&packet).await {
                                        let sender_clone = sender.clone();
                                        let tcp_pipe_context_clone = tcp_pipe_context.clone();
                                        let (sender, mut receiver) = channel::<TunnelPackage>(10);

                                        // 处理隧道返回的数据
                                        spawn(async move {
                                            while let Some(d) = receiver.recv().await {
                                                match d.cmd {
                                                    PackageCmd::Login => {}
                                                    PackageCmd::NewConnect => {}
                                                    PackageCmd::CloseConnect => {
                                                        eprintln!("tunnel send close connect ");
                                                        if let Some(source_addr) = d.source_address {
                                                            if let Some(target_addr) = d.target_address {
                                                                if let Some(pipe) = tcp_pipe_context_clone.get_pipe_by_key(&format!("{}-{}", source_addr, target_addr)).await {
                                                                    let vec = pipe.write().await.do_fin();
                                                                    let _ = sender_clone.send(vec).await;
                                                                } else {
                                                                    eprintln!("get none pipe:{}", &format!("{}-{}", source_addr, target_addr))
                                                                }
                                                                tcp_pipe_context_clone.remove_pipe_by_key(&format!("{}-{}", source_addr, target_addr)).await;
                                                            }
                                                        }
                                                    }
                                                    PackageCmd::TData => {
                                                        if let Some(data) = d.data {
                                                            eprintln!("read tunnel data:{}", data.len());
                                                            if let Some(source_addr) = d.source_address {
                                                                if let Some(target_addr) = d.target_address {
                                                                    if let Some(pipe) = tcp_pipe_context_clone.get_pipe_by_key(&format!("{}-{}", source_addr, target_addr)).await {
                                                                        let vec = pipe.write().await.do_psh(data);
                                                                        let _ = sender_clone.send(vec).await;
                                                                    } else {
                                                                        eprintln!("get none pipe:{}", &format!("{}-{}", source_addr, target_addr))
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    PackageCmd::PING => {}
                                                    PackageCmd::LoginSuccess => {}
                                                    PackageCmd::LoginFail => {}
                                                    PackageCmd::ProtocolError => {}
                                                    PackageCmd::PONG => {}
                                                    PackageCmd::NONE => {}
                                                }
                                            }
                                        });
                                        context.add_proxy_mapping(format!("{}:{}", packet.get_source_addr(), packet.get_source_port()), sender).await;
                                        let _ = context.tunnel_connect_server(format!("{}:{}", packet.get_target_addr(), packet.get_target_port()),
                                                                              format!("{}:{}", packet.get_source_addr(), packet.get_source_port())).await;
                                        let vec = tcp_pipe.read().await.do_ack_syn(&mut packet);
                                        eprintln!("do ack syn , send to client:  ");
                                        // print(vec.as_slice());
                                        let _ = sender1.send(vec).await;
                                        break 'lo;
                                    }
                                }
                                if packet.is_ack() {
                                    eprintln!("packet ack ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                                }
                                // 处理客户端推送过来的的数据
                                if packet.is_psh() {
                                    eprintln!("packet psh ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                                    if let Some(tcp_pipe) = tcp_pipe_context1.get_pipe(&packet).await {
                                        // 发送数据到隧道
                                        eprintln!("send data to tunnel size:{}", packet.get_data().len());
                                        if packet.get_data().len() > 0 {
                                            let _ = context.tunnel_send_data(format!("{}:{}", packet.get_target_addr(), packet.get_target_port()),
                                                                             format!("{}:{}", packet.get_source_addr(), packet.get_source_port()),
                                                                             packet.get_data().to_vec(), PackageProtocol::TCP).await;
                                        }
                                        let vec = tcp_pipe.write().await.do_ack_psh(&mut packet);
                                        eprintln!("do ack psh ,send to client: ");
                                        // print(vec.as_slice());
                                        let _ = sender1.send(vec).await;
                                    } else {
                                        eprintln!("not pipe");
                                    }
                                }
                                // 处理客户端Fin数据包
                                if packet.is_fin() {
                                    eprintln!("packet fin ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                                    if let Some(tcp_pipe) = tcp_pipe_context1.get_pipe(&packet).await {
                                        tcp_pipe_context1.remove_pipe(&packet).await;
                                        // 发送数据到隧道
                                        if packet.get_data().len() > 0 {
                                            let _ = context.tunnel_close_server(format!("{}:{}", packet.get_source_addr(), packet.get_source_port())).await;
                                        }
                                        let vec = tcp_pipe.write().await.do_ack_fin(&mut packet);
                                        eprintln!("do ack fin ,send to client: ");
                                        // print(vec.as_slice());
                                        let _ = sender1.send(vec).await;
                                    } else {
                                        eprintln!("not pipe");
                                    }
                                }
                            }
                            Protocol::UDP => {}
                            Protocol::Unknown => {}
                        }
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
    // for byte in bytes {
    //     print!("{:02x} ", byte);
    // }
    // println!();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open
        ("/Users/lijiacheng/Downloads/rust_file").unwrap();

    let _ = file.write_all("00000000 ".as_bytes());
    for byte in bytes {
        let _ = file.write_all(format!("{:02x} ", byte).as_bytes());
    }
    let _ = file.write_all("\n".as_bytes());
}