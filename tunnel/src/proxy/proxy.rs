use std::io::Error;
use std::process::Output;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::spawn;
use tokio::task::JoinHandle;

use crate::context::context::TunnelContext;
use crate::proxy::proxy_client;

pub struct Proxy {
    port: usize,
    context: Arc<Box<TunnelContext>>,
    tcp_listener_join_handler: Option<JoinHandle<Output>>,
}


impl Proxy {
    pub fn new(context: Arc<Box<TunnelContext>>, port: usize) -> Proxy {
        Proxy {
            port,
            context,
            tcp_listener_join_handler: None,
        }
    }
    /// 启动代理
    pub async fn start(&mut self) -> Result<(), Error> {
        let context = self.context.clone();
        match TcpListener::bind(("0.0.0.0", self.port as u16)).await {
            Ok(lis) => {
                eprintln!("Proxy start on {:}", self.port);
                self.tcp_listener_join_handler = Some(Self::start_accept_client(lis, context));
                Ok(())
            }
            Err(e) => { Err(e) }
        }
    }
    /// 接收客户端的连接
    fn start_accept_client(tcp_listener: TcpListener, context: Arc<Box<TunnelContext>>) -> JoinHandle<Output> {
        let context = context.clone();
        return spawn(async move {
            loop {
                let context = context.clone();
                match tcp_listener.accept().await {
                    Ok((tcp_stream, socket_addr)) => {
                        spawn(async move {
                            // 处理客户端的连接
                            proxy_client::handler_client(tcp_stream, socket_addr, context).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("accept err {}", e);
                    }
                }
            }
        });
    }

    /// 停止监听
    pub fn stop_listener(&mut self) {
        if let Some(job_handler) = self.tcp_listener_join_handler.take() {
            job_handler.abort();
            eprintln!("stop listener");
        }
    }
}
