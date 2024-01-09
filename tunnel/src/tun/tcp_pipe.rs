use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::tun::packet::Packet;
use crate::tun::tcp_pipe_context::{get_pipe_by_key, remove_pipe_by_key};
use crate::tunnel::tunnel_package::{PackageCmd, TunnelPackage};

pub struct TcpPipe {
    source_addr: Ipv4Addr,
    source_port: u16,
    target_addr: Ipv4Addr,
    target_port: u16,
    identification: u32,
    client_sequence_number: u32,
    sequence_number: u32,
    acknowledgment_number: u32,
    tunnel_read_join_handler: JoinHandle<()>,
    tunnel_sender: Sender<TunnelPackage>,
}

impl TcpPipe {
    pub fn new(
        source_addr: Ipv4Addr,
        source_port: u16,
        target_addr: Ipv4Addr,
        target_port: u16,
        client_sequence_number: u32,
        client_sender: Sender<Vec<u8>>,
        pipe_map: Arc<RwLock<HashMap<String, Arc<RwLock<TcpPipe>>>>>,
    ) -> TcpPipe {
        let (tunnel_sender, tunnel_receiver) = channel::<TunnelPackage>(10);
        TcpPipe {
            source_addr,
            source_port,
            target_addr,
            target_port,
            identification: 0,
            client_sequence_number,
            sequence_number: 0,
            acknowledgment_number: 0,
            tunnel_read_join_handler: Self::create_tunnel_read_join_handler(tunnel_receiver, client_sender.clone(), pipe_map),
            tunnel_sender,
        }
    }

    pub fn create_tunnel_read_join_handler(mut tunnel_receiver: Receiver<TunnelPackage>,
                                           client_sender: Sender<Vec<u8>>,
                                           pipe_map: Arc<RwLock<HashMap<String, Arc<RwLock<TcpPipe>>>>>) -> JoinHandle<()> {
        // 处理隧道返回的数据
        spawn(async move {
            while let Some(d) = tunnel_receiver.recv().await {
                match d.cmd {
                    PackageCmd::Login => {}
                    PackageCmd::NewConnect => {}
                    PackageCmd::CloseConnect => {
                        log::error!("tunnel send close connect ");
                        if let Some(source_addr) = d.source_address {
                            if let Some(target_addr) = d.target_address {
                                if let Some(pipe) = get_pipe_by_key(&pipe_map, &format!("{}-{}", source_addr, target_addr)).await {
                                    let vec = pipe.write().await.do_fin();
                                    let _ = client_sender.send(vec).await;
                                } else {
                                    log::error!("get none pipe:{}", &format!("{}-{}", source_addr, target_addr))
                                }
                                remove_pipe_by_key(&pipe_map, &format!("{}-{}", source_addr, target_addr)).await;
                            }
                        }
                    }
                    PackageCmd::TData => {
                        if let Some(data) = d.data {
                            log::error!("read tunnel data:{}", data.len());
                            if let Some(source_addr) = d.source_address {
                                if let Some(target_addr) = d.target_address {
                                    if let Some(pipe) = get_pipe_by_key(&pipe_map, &format!("{}-{}", source_addr, target_addr)).await {
                                        let mtu = 1000;
                                        for x in data.chunks(mtu) {
                                            let vec = pipe.write().await.do_psh(x.to_vec());
                                            let _ = client_sender.send(vec).await;
                                        }
                                    } else {
                                        log::error!("get none pipe:{}", &format!("{}-{}", source_addr, target_addr))
                                    }
                                }
                            }
                        }
                    }
                    PackageCmd::PING => {}
                    PackageCmd::LoginSuccess => {}
                    PackageCmd::LoginFail => {}
                    PackageCmd::ProtocolError => {}
                    PackageCmd::PONG => {}
                    PackageCmd::NONE => {}
                }
            }
        })
    }

    pub fn get_tunnel_sender(&self)->Sender<TunnelPackage>{
        self.tunnel_sender.clone()
    }

    pub fn get_sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// 回应Syn数据包
    pub fn do_ack_syn(&mut self, packet: &mut Packet) -> Vec<u8> {
        self.acknowledgment_number = packet.get_sequence_number() + 1;
        let mut create_packet = Packet::build_tcp_packet(self.identification,
                                                         self.target_addr, self.source_addr,
                                                         self.target_port, self.source_port,
                                                         None);
        create_packet.set_syn();
        create_packet.set_ack();

        create_packet.set_sequence_number(self.sequence_number);
        create_packet.set_acknowledgment_number(self.acknowledgment_number);

        create_packet.calculate_checksum();
        create_packet.calculate_ip_checksum();

        self.sequence_number += 1;

        create_packet.to_byte()
    }

    /// 回应Psh数据包
    pub fn do_ack_psh(&mut self, packet: &mut Packet) -> Vec<u8> {
        self.sequence_number = packet.get_acknowledgment_number();
        self.acknowledgment_number = packet.get_sequence_number() + packet.get_data().len() as u32;
        self.identification += 1;
        let mut create_packet = Packet::build_tcp_packet(self.identification,
                                                         self.target_addr, self.source_addr,
                                                         self.target_port, self.source_port,
                                                         None);
        create_packet.set_ack();

        create_packet.set_sequence_number(self.sequence_number);
        create_packet.set_acknowledgment_number(self.acknowledgment_number);
        create_packet.set_identification(self.identification);

        create_packet.calculate_checksum();
        create_packet.calculate_ip_checksum();

        create_packet.to_byte()
    }

    /// 发送Psh数据包
    pub fn do_psh(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.identification += 1;
        let data_len = data.len() as u32;
        let mut create_packet = Packet::build_tcp_packet(self.identification,
                                                         self.target_addr, self.source_addr,
                                                         self.target_port, self.source_port,
                                                         Some(data));
        create_packet.set_ack();

        create_packet.set_sequence_number(self.sequence_number);
        create_packet.set_acknowledgment_number(self.acknowledgment_number);
        create_packet.set_identification(self.identification);

        create_packet.calculate_checksum();
        create_packet.calculate_ip_checksum();

        self.sequence_number += data_len;

        create_packet.to_byte()
    }

    /// 发送Fin数据包
    pub fn do_fin(&mut self) -> Vec<u8> {
        let mut create_packet = Packet::build_tcp_packet(self.identification,
                                                         self.target_addr, self.source_addr,
                                                         self.target_port, self.source_port,
                                                         None);
        create_packet.set_ack();
        create_packet.set_fin();

        create_packet.set_sequence_number(self.sequence_number);
        create_packet.set_acknowledgment_number(self.acknowledgment_number);

        create_packet.calculate_checksum();
        create_packet.calculate_ip_checksum();

        self.sequence_number += 1;

        create_packet.to_byte()
    }

    /// 回应Fin数据包
    pub fn do_ack_fin(&mut self, packet: &mut Packet) -> Vec<u8> {
        // self.sequence_number = packet.get_acknowledgment_number();
        self.acknowledgment_number = packet.get_sequence_number() + 1;
        self.identification += 1;

        let mut create_packet = Packet::build_tcp_packet(self.identification,
                                                         self.target_addr, self.source_addr,
                                                         self.target_port, self.source_port,
                                                         None);
        create_packet.set_ack();
        create_packet.set_fin();

        create_packet.set_sequence_number(self.sequence_number);
        create_packet.set_acknowledgment_number(self.acknowledgment_number);
        create_packet.set_identification(self.identification);

        create_packet.calculate_checksum();
        create_packet.calculate_ip_checksum();

        create_packet.to_byte()
    }
}