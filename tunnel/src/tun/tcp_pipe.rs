use std::net::Ipv4Addr;

use crate::tun::packet::Packet;

pub struct TcpPipe {
    source_addr: Ipv4Addr,
    source_port: u16,
    target_addr: Ipv4Addr,
    target_port: u16,
    identification: u32,
    client_sequence_number: u32,
    sequence_number: u32,
    acknowledgment_number: u32,
}

impl TcpPipe {
    pub fn new(
        source_addr: Ipv4Addr,
        source_port: u16,
        target_addr: Ipv4Addr,
        target_port: u16,
        client_sequence_number: u32,
    ) -> TcpPipe {
        TcpPipe {
            source_addr,
            source_port,
            target_addr,
            target_port,
            identification: 0,
            client_sequence_number,
            sequence_number: 0,
            acknowledgment_number: 0,
        }
    }

    pub fn get_sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// 回应Syn数据包
    pub fn do_ack_syn(&self, packet: &mut Packet) -> Vec<u8> {
        let mut create_packet = Packet::build_tcp_packet(self.identification,
                                                         self.target_addr, self.source_addr,
                                                         self.target_port, self.source_port,
                                                         None);
        create_packet.set_syn();
        create_packet.set_ack();

        create_packet.set_acknowledgment_number(packet.get_sequence_number() + 1);
        create_packet.set_sequence_number(self.sequence_number);

        create_packet.calculate_checksum();
        create_packet.calculate_ip_checksum();

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