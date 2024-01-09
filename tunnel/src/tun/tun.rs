use std::sync::Arc;

use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::context::context::TunnelContext;
use crate::tun::packet::{Packet, Protocol, Version};
use crate::tun::tcp_pipe_context::TcpPipeContext;
use crate::tunnel::tunnel_package::PackageProtocol;

pub struct Tun {
    client_receiver: RwLock<Receiver<Vec<u8>>>,
    tun_sender: Sender<Vec<u8>>,
    create_tun_data_join_handler: JoinHandle<()>,
}

impl Tun {
    pub fn new(context: Arc<TunnelContext>) -> Self {
        let (client_sender, client_receiver) = channel::<Vec<u8>>(10);
        let (tun_sender, tun_receiver) = channel::<Vec<u8>>(10);
        Tun {
            client_receiver: RwLock::new(client_receiver),
            tun_sender,
            create_tun_data_join_handler: Self::create_tun_data_join_handler(client_sender.clone(),
                                                                             context,
                                                                             Arc::new(TcpPipeContext::new(client_sender.clone())),
                                                                             tun_receiver),
        }
    }

    fn create_tun_data_join_handler(client_sender: Sender<Vec<u8>>,
                                    context: Arc<TunnelContext>,
                                    tcp_pipe_context: Arc<TcpPipeContext>,
                                    mut tun_receiver: Receiver<Vec<u8>>) -> JoinHandle<()> {
        let sender = client_sender.clone();
        let context = context.clone();
        let tcp_pipe_context = tcp_pipe_context.clone();

        spawn(async move {
            while let Some(data) = tun_receiver.recv().await {
                // print("write",data.as_slice());
                log::error!("tun_receiver.recv()");
                let data_len = data.len();

                let mut packet = Packet::from_byte(data);
                let packet_len = packet.get_total_len();
                if packet_len == -1 || data_len < packet_len as usize {
                    return;
                }

                if packet.get_version() == Version::IPV4 {
                    log::error!("read client data: ");
                    match packet.get_protocol() {
                        Protocol::ICMP => {}
                        Protocol::TCP => {
                            // 握手
                            if packet.is_syn() {
                                log::error!("packet syn ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                                if let Some(tcp_pipe) = tcp_pipe_context.create_pipe(&packet).await {
                                    // 隧道映射
                                    context.add_proxy_mapping(format!("{}:{}", packet.get_source_addr(), packet.get_source_port()),
                                                              tcp_pipe.read().await.get_tunnel_sender()).await;
                                    // 发送连接目标命令
                                    let _ = context.tunnel_connect_server(format!("{}:{}", packet.get_target_addr(), packet.get_target_port()),
                                                                          format!("{}:{}", packet.get_source_addr(), packet.get_source_port())).await;
                                    // 响应Syn数据包
                                    let vec = tcp_pipe.write().await.do_ack_syn(&mut packet);
                                    log::error!("do ack syn , send to client:  ");
                                    // print("ack syn",vec.as_slice());
                                    let _ = sender.send(vec).await;
                                }
                            }
                            if packet.is_ack() {
                                log::error!("packet ack ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                            }
                            // 处理客户端推送过来的的数据
                            if packet.is_psh() {
                                log::error!("packet psh ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                                if let Some(tcp_pipe) = tcp_pipe_context.get_pipe(&packet).await {
                                    // 发送数据到隧道
                                    log::error!("send data to tunnel size:{}", packet.get_data().len());
                                    if packet.get_data().len() > 0 {
                                        let _ = context.tunnel_send_data(format!("{}:{}", packet.get_target_addr(), packet.get_target_port()),
                                                                         format!("{}:{}", packet.get_source_addr(), packet.get_source_port()),
                                                                         packet.get_data().to_vec(), PackageProtocol::TCP).await;
                                    }
                                    // 响应Psh数据包
                                    let vec = tcp_pipe.write().await.do_ack_psh(&mut packet);
                                    log::error!("do ack psh ,send to client: ");
                                    // print("ack psh",vec.as_slice());
                                    let _ = sender.send(vec).await;
                                } else {
                                    log::error!("not pipe");
                                }
                            }
                            // 处理客户端Fin数据包
                            if packet.is_fin() {
                                log::error!("packet fin ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                                if let Some(tcp_pipe) = tcp_pipe_context.get_pipe(&packet).await {
                                    tcp_pipe_context.remove_pipe(&packet).await;
                                    // 发送数据到隧道
                                    if packet.get_data().len() > 0 {
                                        let _ = context.tunnel_close_server(format!("{}:{}", packet.get_source_addr(), packet.get_source_port())).await;
                                    }
                                    // 响应Fin数据包
                                    let vec = tcp_pipe.write().await.do_ack_fin(&mut packet);
                                    log::error!("do ack fin ,send to client: ");
                                    // print("ack fin",vec.as_slice());
                                    let _ = sender.send(vec).await;
                                } else {
                                    log::error!("not pipe");
                                }
                            }
                        }
                        Protocol::UDP => {}
                        Protocol::Unknown => {}
                    }
                }
            };
        })
    }

    /// 获取需要发送Tun网卡的数据
    pub async fn get_tun_data(&self) -> Vec<u8> {
        if let Some(data) = self.client_receiver.write().await.recv().await {
            // print("read data",data.as_slice());
            log::error!("write data from tun ,len: {}", data.len());
            data
        } else {
            vec![]
        }
    }

    /// 处理Tun数据包
    pub async fn handler_tun_data(&self, data: Vec<u8>) {
        let _ = self.tun_sender.send(data).await;
    }
}