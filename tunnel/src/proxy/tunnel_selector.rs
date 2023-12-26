use std::sync::Arc;

use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::context::context::TunnelContext;
use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

/// 选择隧道和连接
/// 可以选择直连http或者Socks或者隧道
pub async fn select_and_connect(header_data: Vec<u8>,
                                client_sender: Sender<Vec<u8>>,
                                server_receiver: Receiver<Vec<u8>>,
                                source_addr: String,
                                context: Arc<Box<TunnelContext>>) -> Result<(), String> {
    if header_data.len() < 3 {
        return Err("error data len".to_string());
    }
    // socks5 字节头
    if header_data[0] == 0x05 {
        // 并且没密码校验
        if header_data[2] == 0x00 {
            let _ = client_sender.send([0x05, 0x00].to_vec()).await;
        } else {
            let _ = client_sender.send([0x05, 0xff].to_vec()).await;
            return Err("socks need auth".to_string());
        }
    }
    // http
    else {
        let header_line = unsafe { String::from_utf8_unchecked(header_data.clone()) };

        // https
        return if header_line.starts_with("CONNECT") {
            if let Some(captures) = Regex::new("CONNECT (.+):(.+) HTTP/(1\\.[01])").unwrap().captures(&header_line)
            {
                let host = captures.get(1).unwrap().as_str();
                let port = captures.get(2).unwrap().as_str();
                let _ = client_sender.send("HTTP/1.1 200 Connection Established\r\n\r\n".as_bytes().to_vec()).await;
                proxy_connect(host, port, client_sender, server_receiver, None, source_addr, context).await
            } else {
                Err(format!("https header error :{}", header_line))
            }
        }
        // http
        else {
            let mut split = header_line.split("://");
            split.next();
            let addr = split.next().unwrap().split("\n").next().unwrap();
            let mut split1 = addr.split(":");
            let host = split1.next().unwrap().split("/").next().unwrap();
            let port = if let Some(p) = split1.next() {
                p.split("/").next().unwrap()
            } else { "80" };
            proxy_connect(host, port, client_sender, server_receiver, Some(header_data.clone()), source_addr, context).await
        };
    }

    return Ok(());
}

/// 本地代理连接
pub async fn proxy_connect(host: &str,
                           port: &str,
                           client_sender: Sender<Vec<u8>>,
                           mut server_receiver: Receiver<Vec<u8>>,
                           mut header_data: Option<Vec<u8>>,
                           source_addr: String,
                           context: Arc<Box<TunnelContext>>) -> Result<(), String> {
    if context.tunnel.is_none() {
        eprintln!("not tunnel active");
        return Err("not tunnel active".to_string());
    }

    let host = host.to_string();
    let port = port.to_string();

    // 把发送者交给Context管理
    let (sender_to_proxy, mut tunnel_receiver) = channel::<TunnelPackage>(4096);
    context.proxy_map.write().await.insert(source_addr.to_string(), sender_to_proxy);

    // 发送新建连接命令
    if let Some(proxy_sender) = context.proxy_sender.clone() {
        let _ = proxy_sender.send(TunnelPackage {
            cmd: PackageCmd::NewConnect,
            protocol: PackageProtocol::TCP,
            source_address: Some(source_addr.to_string()),
            target_address: Some(format!("{}:{}", host, port)),
            data: None,
        }).await;
        // 发送传输数据命令
        if let Some(header_data) = header_data.take() {
            let _ = proxy_sender.send(TunnelPackage {
                cmd: PackageCmd::TData,
                protocol: PackageProtocol::TCP,
                source_address: Some(source_addr.to_string()),
                target_address: Some(format!("{}:{}", host, port)),
                data: Some(header_data),
            }).await;
        }

        // 读取Client数据
        spawn(async move {
            while let Some(data) = server_receiver.recv().await {
                let _ = proxy_sender.send(TunnelPackage {
                    cmd: PackageCmd::TData,
                    protocol: PackageProtocol::TCP,
                    source_address: Some(source_addr.to_string()),
                    target_address: Some(format!("{}:{}", host, port)),
                    data: Some(data),
                }).await;
            }
        });

        // 读取Tunnel数据
        while let Some(package) = tunnel_receiver.recv().await {
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
                    return Err("not tunnel active".to_string());
                }
                _ => { break; }
            }
        }
        return Ok(());
    } else {
        eprintln!("not active tunnel");
        return Err("not tunnel active".to_string());
    }


    // match TcpStream::connect(format!("{}:{}", host, port)).await {
    //     Ok(server_stream) => {
    //         eprintln!("Connect Target Success: {:}:{:}", host, port);
    //
    //         let (mut server_reader, mut server_writer) = server_stream.into_split();
    //         if let Some(d) = header_data {
    //             let _ = server_writer.write_all(d.as_slice()).await;
    //         }
    //         spawn(async move {
    //             let mut server_buffer = [0u8; 4096];
    //             loop {
    //                 match server_reader.read(&mut server_buffer).await {
    //                     Ok(0) => {
    //                         eprintln!("disconnect server");
    //                         break;
    //                     }
    //                     Ok(n) => {
    //                         // eprintln!("read server :{}", n);
    //                         let server_data = &server_buffer[..n];
    //
    //                         // let str = String::from_utf8_lossy(server_data);
    //                         // eprintln!("read server content:{}", str);
    //
    //                         if let Err(e) = client_sender.send(server_data.to_vec()).await {
    //                             break;
    //                         }
    //                     }
    //                     Err(e) => {
    //                         eprintln!("connect server {}", e);
    //                         break;
    //                     }
    //                 }
    //             }
    //         });
    //         while let Some(client_data) = server_receiver.recv().await {
    //             let client_data = client_data.as_slice();
    //             // eprintln!("write server data:{}", client_data.len());
    //
    //             // let str = String::from_utf8_lossy(client_data);
    //             // eprintln!("write server data content:{}", str);
    //
    //             if let Err(e) = server_writer.write_all(client_data).await {
    //                 eprintln!("Connect Target {}:{} Error: {:}", host, port, e);
    //                 break;
    //             }
    //         }
    //     }
    //     Err(e) => {
    //         eprintln!("Connect Target {}:{} Error: {:}", host, port, e);
    //         client_sender.closed().await;
    //     }
    // }
}