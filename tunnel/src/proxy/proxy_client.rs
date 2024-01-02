use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Sender};

use crate::context::context::TunnelContext;
use crate::proxy::{http_handler, socks5_handler};

#[derive(PartialEq)]
enum ConnectStatus {
    Init,
    Connected,
    Http,
    Socks5,
}

/// 创建客户端写数据线程
fn create_client_writer(mut writer: OwnedWriteHalf) -> Sender<Vec<u8>> {
    let (sender, mut receiver) = channel::<Vec<u8>>(10);

    spawn(async move {
        while let Some(data) = receiver.recv().await {
            let slice_data = data.as_slice();
            match writer.write_all(slice_data).await {
                Ok(_) => {}
                Err(_) => { break; }
            }
        }
    });

    return sender;
}

/// 处理客户端的连接
pub async fn handler_client(tcp_stream: TcpStream, socket_addr: String, context: Arc<TunnelContext>) {
    // eprintln!("handler client:{}", socket_addr);
    let mut status = ConnectStatus::Init;
    let (mut client_reader, client_writer) = tcp_stream.into_split();
    // 创建客户端写线程
    let client_sender = create_client_writer(client_writer);
    // 服务端发送者
    let mut server_sender: Option<Sender<Vec<u8>>> = None;

    let mut buffer = [0u8; 4096];
    loop {
        match client_reader.read(&mut buffer).await {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                let data = &buffer[..n];

                if status == ConnectStatus::Init {
                    if n < 3 {
                        eprintln!("error data len:{}", n);
                        break;
                    }
                    // socks5 字节头
                    if data[0] == 0x05 {
                        // 并且没密码校验
                        if data[2] == 0x00 {
                            // 发送连接成功
                            let _ = client_sender.send([0x05, 0x00].to_vec()).await;
                            status = ConnectStatus::Socks5;
                            continue;
                        } else {
                            // 发送错误
                            let _ = client_sender.send([0x05, 0xff].to_vec()).await;
                            eprintln!("socks need auth");
                            break;
                        }
                    } else {
                        status = ConnectStatus::Http;
                    }
                }
                if status == ConnectStatus::Socks5 || status == ConnectStatus::Http {
                    let vec = data.to_vec();
                    let sender = client_sender.clone();
                    let (server_sender1, server_receiver) = channel::<Vec<u8>>(10);
                    server_sender = Some(server_sender1);
                    let context = context.clone();
                    let context2 = context.clone();
                    let socket_addr = socket_addr.clone();
                    if status == ConnectStatus::Http {
                        spawn(async move {
                            // 连接服务端 返回服务端的发送者
                            let e = http_handler::handle(vec, sender.clone(), server_receiver, socket_addr.clone(), context).await;
                            eprintln!("proxy client err {}", e);
                            context2.remove_connect_info(&socket_addr).await;
                        });
                    } else {
                        spawn(async move {
                            // 连接服务端 返回服务端的发送者
                            let e = socks5_handler::handle(vec, sender.clone(), server_receiver, socket_addr.clone(), context).await;
                            eprintln!("proxy client err {}", e);
                            context2.remove_connect_info(&socket_addr).await;
                        });
                    }
                    status = ConnectStatus::Connected;
                } else if status == ConnectStatus::Connected {
                    if let Some(s) = server_sender.take() {
                        if let Err(_) = s.send(data.to_vec()).await {
                            break;
                        }
                        server_sender = Some(s);
                    } else {
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("read {} Error: {:}", socket_addr, e);
                break;
            }
        }
    }

    context.remove_proxy_mapping(socket_addr.to_string()).await;
    let _ = context.tunnel_close_server(socket_addr.to_string()).await;
    context.remove_connect_info(&socket_addr).await;
    // eprintln!("proxy client loop end ");
}