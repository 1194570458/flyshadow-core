use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::context::context::TunnelContext;
use crate::context::proxy_type::ProxyType;
use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

pub async fn handle(header_data: Vec<u8>,
                    client_sender: Sender<Vec<u8>>,
                    mut client_receiver: Receiver<Vec<u8>>,
                    source_addr: String,
                    context: Arc<TunnelContext>) -> String {
    let header_data_len = header_data.len();
    let command = header_data[1];
    let address_type = header_data[3];

    let domain = match address_type {
        // IPV4
        0x01 => {
            Ipv4Addr::new(
                header_data[4], header_data[5], header_data[6], header_data[7],
            ).to_string()
        }
        // Domain
        0x03 => {
            let len = header_data[4];
            let mut data = Vec::<u8>::new();
            for i in 0..len {
                data.push(header_data[(i + 5) as usize]);
            }
            String::from_utf8_lossy(data.as_slice()).to_string()
        }
        // IPV6
        0x04 => {
            let mut data = [0u8; 16];
            for i in 0..16 {
                data[i] = header_data[i + 4];
            }
            Ipv6Addr::from(data).to_string()
        }
        _ => { "".to_string() }
    };

    let proxy_type = context.match_domain(&domain).await;

    let port = (((header_data[header_data_len - 2] & 0xff) as i32) << 8) | ((header_data[header_data_len - 1] & 0xff) as i32);

    // TCP
    if command == 0x01 {
        // 响应TCP连接
        let _ = client_sender.send(vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;

        match proxy_type {
            ProxyType::Redirect => {
                eprintln!("{} Redirect", domain);
                match TcpStream::connect(format!("{}:{}", domain, port)).await {
                    Ok(server_stream) => {
                        eprintln!("Connect Target Success: {:}:{:}", domain, port);

                        let (mut server_reader, mut server_writer) = server_stream.into_split();
                        spawn(async move {
                            let mut server_buffer = [0u8; 4096];
                            loop {
                                match server_reader.read(&mut server_buffer).await {
                                    Ok(0) => {
                                        eprintln!("disconnect server");
                                        break;
                                    }
                                    Ok(n) => {
                                        let server_data = &server_buffer[..n];
                                        if let Err(_e) = client_sender.send(server_data.to_vec()).await {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("connect server {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                        while let Some(client_data) = client_receiver.recv().await {
                            let client_data = client_data.as_slice();
                            if let Err(e) = server_writer.write_all(client_data).await {
                                eprintln!("Write Target {}:{} Error: {:}", domain, port, e);
                            }
                        }
                        return "".to_string();
                    }
                    Err(e) => {
                        eprintln!("Connect Target {}:{} Error: {:}", domain, port, e);
                        return e.to_string();
                    }
                }
            }
            ProxyType::Reject => {
                return format!("Reject: {}", domain);
            }
            ProxyType::Proxy => {
                eprintln!("{} Proxy", domain);
                let host = domain.to_string();
                let port = port.to_string();

                // 连接服务端
                match context.tunnel_connect_server(format!("{}:{}", host, port), source_addr.to_string()).await {
                    Ok(_) => {}
                    Err(e) => { return e; }
                }

                // 添加映射
                let (sender_to_proxy, mut tunnel_receiver) = channel::<TunnelPackage>(10);
                context.add_proxy_mapping(source_addr.to_string(), sender_to_proxy).await;

                // 循环读取Client数据
                let context_clone = context.clone();
                let source_addr_clone = source_addr.clone();
                let target_addr = format!("{}:{}", host, port);
                spawn(async move {
                    while let Some(data) = client_receiver.recv().await {
                        match context_clone.tunnel_send_data(target_addr.to_string(), source_addr_clone.to_string(), data, PackageProtocol::TCP).await {
                            Ok(_) => {}
                            Err(_) => { break; }
                        }
                    }
                });

                // 读取Tunnel数据
                while let Some(package) = tunnel_receiver.recv().await {
                    // eprintln!("receiver package {:?}",package);
                    match package.cmd {
                        PackageCmd::CloseConnect => { break; }
                        PackageCmd::TData => {
                            if let Some(data) = package.data {
                                let _ = client_sender.send(data).await;
                            }
                        }
                        PackageCmd::PING => {}
                        PackageCmd::LoginSuccess => {}
                        PackageCmd::LoginFail => { break; }
                        PackageCmd::ProtocolError => { break; }
                        PackageCmd::PONG => {}
                        PackageCmd::NONE => {
                            eprintln!("not active tunnel");
                            return "not tunnel active".to_string();
                        }
                        _ => {}
                    }
                }

                return "".to_string();
            }
        }
    }
    // UDP
    else if command == 0x03 {
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => { s }
            Err(e) => { return e.to_string(); }
        };
        let (udp_addr, udp_port) = match socket.local_addr() {
            Ok(a) => { (a.ip().to_string(), a.port()) }
            Err(e) => { return e.to_string(); }
        };
        // 响应
        let _ = client_sender.send(vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, (udp_port >> 8) as u8, udp_port as u8]).await;

        let socket = Arc::new(socket);


        let mut buf = [0u8; 4096];
        loop {
            // 读UDP数据
            match socket.recv_from(&mut buf).await {
                Ok((n, addr)) => {
                    let data = &buf[..n];
                    let mut last_domain_index = 0;
                    // 解析目标地址
                    let target_domain = match data[3] {
                        0x01 => {
                            last_domain_index = 8;
                            Ipv4Addr::new(
                                data[4], data[5], data[6], data[7],
                            ).to_string()
                        }
                        0x03 => {
                            let len = data[4];
                            last_domain_index = 4 + len;
                            let mut data = Vec::<u8>::new();
                            for i in 0..len {
                                data.push(data[(i + 5) as usize]);
                            }
                            String::from_utf8_lossy(data.as_slice()).to_string()
                        }
                        0x04 => {
                            last_domain_index = 20;
                            let mut temp_data = [0u8; 16];
                            for i in 0..16 {
                                temp_data[i] = data[i + 4];
                            }
                            Ipv6Addr::from(temp_data).to_string()
                        }
                        _ => { return "".to_string(); }
                    };
                    let port = (((data[last_domain_index as usize] & 0xff) as i32) << 8) | ((data[(last_domain_index + 1) as usize] & 0xff) as i32);

                    context.tunnel_send_data(format!("{}:{}", target_domain, port))

                    // 添加映射
                    let (sender_to_proxy, mut tunnel_receiver) = channel::<TunnelPackage>(10);
                    context.add_proxy_mapping(addr.to_string(), sender_to_proxy).await;
                }
                Err(e) => { return e.to_string(); }
            }
        }


        // 读取Tunnel数据
        while let Some(package) = tunnel_receiver.recv().await {
            match package.cmd {
                PackageCmd::CloseConnect => { break; }
                PackageCmd::TData => {
                    if let Some(data) = package.data {
                        let _ = socket.send_to(data.as_slice(), "").await;
                    }
                }
                PackageCmd::PING => {}
                PackageCmd::LoginSuccess => {}
                PackageCmd::LoginFail => { break; }
                PackageCmd::ProtocolError => { break; }
                PackageCmd::PONG => {}
                PackageCmd::NONE => {
                    eprintln!("not active tunnel");
                    return "not tunnel active".to_string();
                }
                _ => {}
            }
        }
    }

    return "".to_string();
}