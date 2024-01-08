use std::collections::HashMap;
use std::sync::Arc;
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::tun::packet::Packet;
use crate::tun::tcp_pipe::TcpPipe;
use crate::tunnel::tunnel_package::{PackageCmd, TunnelPackage};

pub struct TcpPipeContext {
    pipe_map: Arc<RwLock<HashMap<String, Arc<RwLock<TcpPipe>>>>>,
    client_sender: Sender<Vec<u8>>,
}


impl TcpPipeContext {
    pub fn new(client_sender: Sender<Vec<u8>>) -> Self {
        let pipe_map = Arc::new(RwLock::new(HashMap::new()));
        TcpPipeContext {
            pipe_map: pipe_map.clone(),
            client_sender: client_sender.clone(),
        }
    }
}

impl TcpPipeContext {
    /// 创建管道
    pub async fn create_pipe(&self, packet: &Packet) -> Option<Arc<RwLock<TcpPipe>>> {
        if !packet.is_syn() {
            return None;
        }
        let key = format!("{}:{}-{}:{}",
                          packet.get_source_addr(),
                          packet.get_source_port(),
                          packet.get_target_addr(),
                          packet.get_target_port());
        if let Some(pipe) = self.pipe_map.read().await.get(&key) {
            if pipe.read().await.get_sequence_number() == packet.get_sequence_number() {
                return None;
            }
        }

        let tcp_pipe = Arc::new(RwLock::new(TcpPipe::new(packet.get_source_addr(),
                                                         packet.get_source_port(),
                                                         packet.get_target_addr(),
                                                         packet.get_target_port(),
                                                         packet.get_sequence_number(),
                                                         self.client_sender.clone(),
                                                         self.pipe_map.clone())));
        {
            self.pipe_map.write().await.insert(key.clone(), Arc::clone(&tcp_pipe));
        }
        return Some(tcp_pipe);
    }

    /// 获取管道
    pub async fn get_pipe(&self, packet: &Packet) -> Option<Arc<RwLock<TcpPipe>>> {
        let key = format!("{}:{}-{}:{}",
                          packet.get_source_addr(),
                          packet.get_source_port(),
                          packet.get_target_addr(),
                          packet.get_target_port());
        self.get_pipe_by_key(&key).await
    }

    /// 根据key获取管道
    pub async fn get_pipe_by_key(&self, key: &String) -> Option<Arc<RwLock<TcpPipe>>> {
        return if let Some(arc) = self.pipe_map.read().await.get(key) {
            Some(Arc::clone(arc))
        } else {
            None
        };
    }

    /// 删除管道
    pub async fn remove_pipe(&self, packet: &Packet) {
        let key = format!("{}:{}-{}:{}",
                          packet.get_source_addr(),
                          packet.get_source_port(),
                          packet.get_target_addr(),
                          packet.get_target_port());
        self.remove_pipe_by_key(&key).await;
    }

    /// 根据Key删除管道
    pub async fn remove_pipe_by_key(&self, key: &String) {
        self.pipe_map.write().await.remove(key);
    }
}

/// 根据Key删除管道
pub async fn remove_pipe_by_key(pipe_map: &Arc<RwLock<HashMap<String, Arc<RwLock<TcpPipe>>>>>, key: &String) {
    pipe_map.write().await.remove(key);
}

/// 根据key获取管道
pub async fn get_pipe_by_key(pipe_map: &Arc<RwLock<HashMap<String, Arc<RwLock<TcpPipe>>>>>, key: &String) -> Option<Arc<RwLock<TcpPipe>>> {
    if let Some(arc) = pipe_map.read().await.get(key) {
        Some(Arc::clone(arc))
    } else {
        None
    }
}