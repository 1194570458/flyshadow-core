use std::net::Ipv4Addr;

use crate::tun::packet::Packet;

pub struct TcpPipe {
    source_addr: Ipv4Addr,
    source_port: u16,
    target_addr: Ipv4Addr,
    target_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
}

impl TcpPipe {
    pub fn new(
        source_addr: Ipv4Addr,
        source_port: u16,
        target_addr: Ipv4Addr,
        target_port: u16,
        sequence_number: u32,
    ) -> TcpPipe {
        TcpPipe {
            source_addr,
            source_port,
            target_addr,
            target_port,
            sequence_number,
            acknowledgment_number: 0,
        }
    }

    pub fn get_sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// 设置应答
    pub fn do_syn(&self, packet: &Packet) {}
}