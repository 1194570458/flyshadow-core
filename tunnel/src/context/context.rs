use std::collections::HashMap;
use std::sync::Arc;

use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::tunnel::tunnel::Tunnel;
use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

pub struct TunnelContext {
    tunnel: RwLock<Option<Tunnel>>,
    tunnel_sender: Sender<TunnelPackage>,
    tunnel_receiver: Option<Receiver<TunnelPackage>>,
    proxy_map: Arc<RwLock<HashMap<String, Sender<TunnelPackage>>>>,
    tunnel_receiver_job: Option<JoinHandle<()>>,
}

impl TunnelContext {
    /// 开启tunnel数据包接收线程
    fn start_tunnel_receiver_job(&mut self) {
        let proxy_map = self.proxy_map.clone();
        if let Some(mut tunnel_receiver) = self.tunnel_receiver.take() {
            let tunnel_receiver_job = spawn(async move {
                // 读TunnelPackage
                while let Some(tunnel_package) = tunnel_receiver.recv().await {
                    // 有源地址
                    if let Some(ref source_addr) = tunnel_package.source_address {
                        // 取映射中的客户端
                        if let Some(sender) = proxy_map.read().await.get(&source_addr.to_string()) {
                            let _ = sender.send(tunnel_package).await;
                        }
                    }
                };
            });
            self.tunnel_receiver_job = Some(tunnel_receiver_job);
        }
    }
}

impl TunnelContext {
    pub fn new() -> TunnelContext {
        // Tunnel往这里写  Context读取这里数据 写到对应Tunnel receiver
        let (tunnel_sender, tunnel_receiver) = channel::<TunnelPackage>(10);
        let proxy_map = Arc::new(RwLock::new(HashMap::new()));

        let mut context = TunnelContext {
            tunnel: RwLock::new(None),
            tunnel_sender, // Tunnel往这里写
            tunnel_receiver: Some(tunnel_receiver), // 这里数据转发给Tunnel
            proxy_map: proxy_map.clone(),
            tunnel_receiver_job: None,
        };
        // 开启读取tunnel数据包线程
        context.start_tunnel_receiver_job();
        context
    }

    /// 获取隧道的上传流量
    pub async fn get_tunnel_upload(&self) -> i64 {
        let read_guard = self.tunnel.read().await;
        return if let Some(tunnel) = read_guard.as_ref() {
            tunnel.get_upload().await
        } else {
            0
        };
    }

    /// 获取隧道的下载流量
    pub async fn get_tunnel_download(&self) -> i64 {
        let read_guard = self.tunnel.read().await;
        return if let Some(tunnel) = read_guard.as_ref() {
            tunnel.get_download().await
        } else {
            0
        };
    }

    ///连接Tunnel
    pub async fn connect_tunnel(&self, host: String, port: u16, password: String) -> Result<(), String> {
        let mut write_guard = self.tunnel.write().await;

        if let Some(mut tunnel) = write_guard.take() {
            tunnel.disconnect().await;
        }
        return match Tunnel::new(host, port, password, self.tunnel_sender.clone()).await {
            Ok(tunnel) => {
                *write_guard = Some(tunnel);
                Ok(())
            }
            Err(e) => {
                Err(e.to_string())
            }
        };
    }

    /// 关闭隧道连接
    pub async fn close_tunnel(&self) {
        let mut tunnel_guard = self.tunnel.write().await;
        if let Some(mut tunnel) = tunnel_guard.take(){
            tunnel.disconnect().await;
        }
    }

    /// 添加代理映射
    pub async fn add_proxy_mapping(&self, source_addr: String, sender: Sender<TunnelPackage>) {
        self.proxy_map.write().await.insert(source_addr, sender);
    }

    /// 删除代理映射
    pub async fn remove_proxy_mapping(&self, source_addr: String) {
        self.proxy_map.write().await.remove(&source_addr);
    }

    /// 发送连接服务端命令
    pub async fn tunnel_connect_server(&self, target_addr: String, source_addr: String) -> Result<(), String> {
        eprintln!("connect to: {}", target_addr);
        if self.tunnel.read().await.is_none() {
            return Err("Tunnel is none".to_string());
        }

        let mut write_guard = self.tunnel.write().await;
        if let Some(mut tunnel) = write_guard.take() {
            let tunnel_package = TunnelPackage {
                cmd: PackageCmd::NewConnect,
                protocol: PackageProtocol::TCP,
                source_address: Some(source_addr),
                target_address: Some(target_addr),
                data: None,
            };
            if let Err(e) = tunnel.write_to_tunnel(tunnel_package).await {
                *write_guard = Some(tunnel);
                return Err(e.to_string());
            }
            *write_guard = Some(tunnel);
        } else {
            return Err("Tunnel is none".to_string());
        }

        return Ok(());
    }

    /// 发送数据到Tunnel
    pub async fn tunnel_send_data(&self, target_addr: String, source_addr: String, data: Vec<u8>, protocol: PackageProtocol) -> Result<(), String> {
        if self.tunnel.read().await.is_none() {
            return Err("Tunnel is none".to_string());
        }

        let mut write_guard = self.tunnel.write().await;
        if let Some(mut tunnel) = write_guard.take() {
            let tunnel_package = TunnelPackage {
                cmd: PackageCmd::TData,
                protocol,
                source_address: Some(source_addr),
                target_address: Some(target_addr),
                data: Some(data),
            };
            if let Err(e) = tunnel.write_to_tunnel(tunnel_package).await {
                *write_guard = Some(tunnel);
                return Err(e.to_string());
            }
            *write_guard = Some(tunnel);
        } else {
            return Err("Tunnel is none".to_string());
        }

        return Ok(());
    }

    /// 发送关闭服务端连接命令
    pub async fn tunnel_close_server(&self, source_addr: String) -> Result<(), String> {
        eprintln!("dis connect ,source addr: {}", source_addr);
        if self.tunnel.read().await.is_none() {
            return Err("Tunnel is none".to_string());
        }

        let mut write_guard = self.tunnel.write().await;
        if let Some(mut tunnel) = write_guard.take() {
            let tunnel_package = TunnelPackage {
                cmd: PackageCmd::CloseConnect,
                protocol: PackageProtocol::TCP,
                source_address: Some(source_addr),
                target_address: None,
                data: None,
            };
            let _ = tunnel.write_to_tunnel(tunnel_package).await;
            *write_guard = Some(tunnel);
        } else {
            return Err("Tunnel is none".to_string());
        }

        return Ok(());
    }
}
