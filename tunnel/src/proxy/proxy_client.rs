use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

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
    // 客户端写线程
    let mut client_write_join_handler: Option<JoinHandle<()>> = None;
    // UDP临时端口
    let udp_temp_source_addr: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

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
                        let handler = spawn(async move {
                            // 连接服务端 返回服务端的发送者
                            let e = http_handler::handle(vec, sender.clone(), server_receiver, socket_addr.clone(), context).await;
                            eprintln!("http handler back {}", e);
                            // 回收资源
                            context2.remove_proxy_mapping(&socket_addr).await;
                            let _ = context2.tunnel_close_server(socket_addr.to_string()).await;
                            context2.remove_connect_info(&socket_addr).await;
                        });
                        client_write_join_handler = Some(handler);
                    } else {
                        let udp_temp_source_addr2 = udp_temp_source_addr.clone();
                        let udp_temp_source_addr3 = udp_temp_source_addr.clone();
                        let handler = spawn(async move {
                            // 连接服务端 返回服务端的发送者
                            let e = socks5_handler::handle(vec, sender.clone(), server_receiver, socket_addr.clone(), context, udp_temp_source_addr2).await;
                            eprintln!("socks5 handler back {}", e);
                            // 回收资源
                            context2.remove_proxy_mapping(&socket_addr).await;
                            let _ = context2.tunnel_close_server(socket_addr.to_string()).await;
                            for source_addr in udp_temp_source_addr3.read().await.iter() {
                                context2.remove_proxy_mapping(source_addr).await;
                            }
                            context2.remove_connect_info(&socket_addr).await;
                        });
                        client_write_join_handler = Some(handler);
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

    // 回收资源
    context.remove_proxy_mapping(&socket_addr).await;
    let _ = context.tunnel_close_server(socket_addr.to_string()).await;
    for source_addr in udp_temp_source_addr.read().await.iter() {
        context.remove_proxy_mapping(source_addr).await;
    }
    context.remove_connect_info(&socket_addr).await;
    if let Some(handler) = client_write_join_handler {
        handler.abort();
    };
    // eprintln!("proxy client loop end ");
}