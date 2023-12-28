use std::net::SocketAddr;
use std::process::Output;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Sender};
use tokio::task::JoinHandle;

use crate::context::context::TunnelContext;
use crate::proxy::tunnel_selector;

#[derive(PartialEq)]
enum ConnectStatus {
    INIT,
    CONNECTED,
}

/// 创建客户端写数据线程
fn create_client_writer(mut writer: OwnedWriteHalf) -> Sender<Vec<u8>> {
    let (sender, mut receiver) = channel::<Vec<u8>>(8192);

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
pub async fn handler_client(mut tcp_stream: TcpStream, socket_addr: SocketAddr, context: Arc<TunnelContext>) {
    // eprintln!("handler client:{}", socket_addr);
    let mut status = ConnectStatus::INIT;
    let (mut client_reader, client_writer) = tcp_stream.into_split();
    // 创建客户端写线程
    let client_sender = create_client_writer(client_writer);
    // 服务端发送者
    let mut server_sender: Option<Sender<Vec<u8>>> = None;

    let mut handler_read_data_job_handler:Option<JoinHandle<()>> = None;

    let mut buffer = [0u8; 4096];
    loop {
        match client_reader.read(&mut buffer).await {
            Ok(0) => {
                break;
            }
            Ok(n) => {
                let data = &buffer[..n];

                if status == ConnectStatus::INIT {
                    status = ConnectStatus::CONNECTED;
                    let vec = data.to_vec();
                    let sender = client_sender.clone();
                    let (server_sender1, server_receiver) = channel::<Vec<u8>>(8192);
                    server_sender = Some(server_sender1);
                    let context = context.clone();
                    handler_read_data_job_handler = Some(spawn(async move {
                        // 连接服务端 返回服务端的发送者
                        if let Err(e) = tunnel_selector::select_and_connect(vec, sender.clone(), server_receiver, format!("{}", socket_addr), context).await {
                            eprintln!("proxy client err {}", e);
                        };
                    }));
                } else {
                    if let Some(s) = server_sender.take() {
                        let _ = s.send(data.to_vec()).await;
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

    if let Some(job) = handler_read_data_job_handler{
        job.abort();
    }

    context.remove_proxy_mapping(socket_addr.to_string()).await;
    // eprintln!("proxy client loop end ");
}