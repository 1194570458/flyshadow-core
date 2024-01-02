use std::io::Error;
use std::process::Output;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::spawn;
use tokio::task::JoinHandle;

use crate::context::context::TunnelContext;
use crate::proxy::proxy_client;

pub struct Proxy {
    port: usize,
    context: Arc<TunnelContext>,
    tcp_listener_join_handler: Option<JoinHandle<Output>>,
}


impl Proxy {
    pub fn new(context: Arc<TunnelContext>, port: usize) -> Proxy {
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
                self.start_accept_client(lis, context);
                Ok(())
            }
            Err(e) => { Err(e) }
        }
    }
    /// 接收客户端的连接
    fn start_accept_client(&mut self, tcp_listener: TcpListener, context: Arc<TunnelContext>) {
        let context = context.clone();
        let job_handler = spawn(async move {
            loop {
                let context = context.clone();
                let context2 = context.clone();
                match tcp_listener.accept().await {
                    Ok((tcp_stream, socket_addr)) => {
                        let socket_addr = format!("{}", socket_addr);
                        let socket_addr2 = socket_addr.clone();
                        let join_handler = spawn(async move {
                            // 处理客户端的连接
                            proxy_client::handler_client(tcp_stream, socket_addr, context).await;
                        });
                        context2.create_connect_info(socket_addr2, join_handler).await;
                    }
                    Err(e) => {
                        eprintln!("accept err {}", e);
                    }
                }
            }
        });
        self.tcp_listener_join_handler = Some(job_handler);
    }

    /// 停止监听
    pub fn stop(&mut self) {
        if let Some(job_handler) = self.tcp_listener_join_handler.take() {
            job_handler.abort();
            eprintln!("stop listener");
        }
    }
}
