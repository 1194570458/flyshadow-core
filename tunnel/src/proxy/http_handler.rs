use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::context::context::TunnelContext;
use crate::context::proxy_type::ProxyType;
use crate::proxy::uri_util::{HttpMethod, resolve_uri};
use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

/// 选择隧道和连接
/// 可以选择直连http或者Socks或者隧道
pub async fn handle(header_data: Vec<u8>,
                    client_sender: Sender<Vec<u8>>,
                    client_receiver: Receiver<Vec<u8>>,
                    source_addr: String,
                    context: Arc<TunnelContext>) -> String {
    let (host, port, method) = resolve_uri(&header_data);

    // https
    return if method == HttpMethod::Connect {
        let _ = client_sender.send("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes().to_vec()).await;
        proxy_http_connect(&host, &port, client_sender, client_receiver, None, source_addr, context).await
    }
    // http
    else if method == HttpMethod::Http {
        proxy_http_connect(&host, &port, client_sender, client_receiver, Some(header_data.clone()), source_addr, context).await
    } else {
        format!("Unknown uri :{}", String::from_utf8_lossy(&header_data))
    };
}

/// 本地代理http连接
pub async fn proxy_http_connect(host: &str,
                                port: &str,
                                client_sender: Sender<Vec<u8>>,
                                mut client_receiver: Receiver<Vec<u8>>,
                                mut header_data: Option<Vec<u8>>,
                                source_addr: String,
                                context: Arc<TunnelContext>) -> String {
    return match context.match_domain(&host.to_string()).await {
        ProxyType::Redirect => {
            log::error!("{} Redirect", host);
            match TcpStream::connect(format!("{}:{}", host, port)).await {
                Ok(server_stream) => {
                    log::error!("Connect Target Success: {:}:{:} source_addr: {}", host, port, source_addr);

                    let (mut server_reader, mut server_writer) = server_stream.into_split();
                    if let Some(d) = header_data {
                        let _ = server_writer.write_all(d.as_slice()).await;
                    }
                    spawn(async move {
                        let mut server_buffer = [0u8; 4096];
                        loop {
                            match server_reader.read(&mut server_buffer).await {
                                Ok(0) => {
                                    log::error!("disconnect server");
                                    break;
                                }
                                Ok(n) => {
                                    let server_data = &server_buffer[..n];
                                    if let Err(_e) = client_sender.send(server_data.to_vec()).await {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    log::error!("connect server {}", e);
                                    break;
                                }
                            }
                        }
                    });
                    while let Some(client_data) = client_receiver.recv().await {
                        let client_data = client_data.as_slice();
                        if let Err(e) = server_writer.write_all(client_data).await {
                            log::error!("Write Target {}:{} Error: {:}", host, port, e);
                        }
                    }
                    "".to_string()
                }
                Err(e) => {
                    log::error!("Connect Target {}:{} Error: {:}", host, port, e);
                    e.to_string()
                }
            }
        }
        ProxyType::Reject => {
            format!("Reject: {}", host)
        }
        ProxyType::Proxy => {
            log::error!("{} Proxy", host);
            let host = host.to_string();
            let port = port.to_string();

            // 连接服务端
            match context.tunnel_connect_server(format!("{}:{}", host, port), source_addr.to_string()).await {
                Ok(_) => {}
                Err(e) => { return e; }
            }

            // 添加映射
            let (sender_to_proxy, mut tunnel_receiver) = channel::<TunnelPackage>(10);
            context.add_proxy_mapping(source_addr.to_string(), sender_to_proxy).await;

            // 写请求头部数据
            if let Some(data) = header_data.take() {
                match context.tunnel_send_data(format!("{}:{}", host, port), source_addr.to_string(), data, PackageProtocol::TCP).await {
                    Ok(_) => {}
                    Err(e) => { return e; }
                }
            }

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
                // log::error!("receiver package {:?}",package);
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
                        log::error!("not active tunnel");
                        return "not tunnel active".to_string();
                    }
                    _ => {}
                }
            }

            "".to_string()
        }
    };
}