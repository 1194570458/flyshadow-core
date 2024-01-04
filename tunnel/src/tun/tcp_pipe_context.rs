use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::tun::packet::Packet;
use crate::tun::tcp_pipe::TcpPipe;

pub struct TcpPipeContext {
    pipe_map: RwLock<HashMap<String, Arc<TcpPipe>>>,
}


impl TcpPipeContext {
    pub fn new() -> Self {
        TcpPipeContext {
            pipe_map: RwLock::new(HashMap::new()),
        }
    }
}

impl TcpPipeContext {
    /// 创建管道
    pub async fn create_pipe<'a>(&self, packet: &'a Packet<'a>) -> Option<Arc<TcpPipe>> {
        if !packet.is_syn() {
            return None;
        }
        let key = format!("{}:{}-{}:{}",
                          packet.get_source_addr(),
                          packet.get_source_port(),
                          packet.get_target_addr(),
                          packet.get_target_port());
        if let Some(pipe) = self.pipe_map.read().await.get(&key) {
            if pipe.get_sequence_number() == packet.get_sequence_number() {
                return None;
            }
        }

        let tcp_pipe = Arc::new(TcpPipe::new(
            packet.get_source_addr(),
            packet.get_source_port(),
            packet.get_target_addr(),
            packet.get_source_port(),
            packet.get_sequence_number(),
        ));
        {
            self.pipe_map.write().await.insert(key, Arc::clone(&tcp_pipe));
        }
        return Some(tcp_pipe);
    }
}