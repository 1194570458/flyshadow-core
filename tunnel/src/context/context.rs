use std::collections::HashMap;
use std::sync::Arc;

use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::proxy::proxy::Proxy;
use crate::tunnel::tunnel::Tunnel;
use crate::tunnel::tunnel_package::TunnelPackage;

pub struct TunnelContext {
    proxy: Option<Proxy>,
    pub tunnel: Option<Tunnel>,
    pub tunnel_sender: Option<Sender<TunnelPackage>>,
    pub proxy_sender: Option<Sender<TunnelPackage>>,
    pub tunnel_receiver: Option<Receiver<TunnelPackage>>,
    pub proxy_map: Arc<RwLock<HashMap<String, Sender<TunnelPackage>>>>,
    context_job_handler: JoinHandle<()>,
}

impl TunnelContext {
    pub fn new() -> TunnelContext {
        // Tunnel往这里写  Context读取这里数据 写到对应Tunnel receiver
        let (s1, r1) = channel::<TunnelPackage>(4096);
        let (s2, r2) = channel::<TunnelPackage>(4096);
        let proxy_map = Arc::new(RwLock::new(HashMap::new()));
        TunnelContext {
            proxy: None,
            tunnel: None,
            tunnel_sender: Some(s1), // Tunnel往这里写
            proxy_sender: Some(s2), // Proxy 往这里写
            tunnel_receiver: Some(r2), // 这里数据转发给Tunnel
            proxy_map: proxy_map.clone(),
            context_job_handler: Self::start(proxy_map.clone(), r1),
        }
    }

    pub fn start(proxy_map: Arc<RwLock<HashMap<String, Sender<TunnelPackage>>>>, mut r1: Receiver<TunnelPackage>) -> JoinHandle<()> {
        return spawn(async move {
            while let Some(tunnel_package) = r1.recv().await {
                if let Some(ref sourceAddr) = tunnel_package.source_address {
                    if let Some(sender) = proxy_map.read().await.get(&sourceAddr.to_string()) {
                        let _ = sender.send(tunnel_package).await;
                    }
                }
            };
        });
    }
}
