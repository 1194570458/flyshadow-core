use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub enum Protocol {
    ICMP,
    TCP,
    UDP,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum Version {
    IPV4,
    IPV6,
    Unknown,
}

pub struct Packet<'a> {
    byte_arr: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn from_byte(byte: &[u8]) -> Packet {
        Packet {
            byte_arr: byte,
        }
    }

    /// 获取IP数据包总长
    pub fn get_total_len(&self) -> i32 {
        if self.byte_arr.len() < 4 {
            return -1;
        }
        u16::from_be_bytes([self.byte_arr[2], self.byte_arr[3]]) as i32
    }

    /// 获取IP数据包版本
    pub fn get_version(&self) -> Version {
        match self.byte_arr[0] >> 4 {
            4 => { Version::IPV4 }
            6 => { Version::IPV6 }
            _ => { Version::Unknown }
        }
    }
    /// 获取IP数据包头长度，总字节 = 首部长度 * 4
    pub fn get_ip_header_len(&self) -> usize {
        (self.byte_arr[0] & 0x0f) as usize
    }

    /// 获取IP数据包协议
    pub fn get_protocol(&self) -> Protocol {
        match self.byte_arr[9] {
            1 => { Protocol::ICMP }
            6 => { Protocol::TCP }
            17 => { Protocol::UDP }
            _ => { Protocol::Unknown }
        }
    }

    /// 获取ip数据包校验和
    pub fn get_ip_checksum(&self) -> u16 {
        eprintln!("{:02x?}", [self.byte_arr[10], self.byte_arr[11]]);
        u16::from_be_bytes([self.byte_arr[10], self.byte_arr[11]])
    }

    /// 获取源地址
    pub fn get_source_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([self.byte_arr[12], self.byte_arr[13], self.byte_arr[14], self.byte_arr[15]])
    }

    /// 获取目标地址
    pub fn get_target_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([self.byte_arr[16], self.byte_arr[17], self.byte_arr[18], self.byte_arr[19]])
    }

    /// 获取源端口
    pub fn get_source_port(&self) -> u16 {
        let i = self.get_ip_header_len() * 4;
        u16::from_be_bytes([self.byte_arr[i], self.byte_arr[i + 1]])
    }

    /// 获取目标端口
    pub fn get_target_port(&self) -> u16 {
        let i = self.get_ip_header_len() * 4;
        u16::from_be_bytes([self.byte_arr[i + 2], self.byte_arr[i + 3]])
    }

    /// 获取seq码
    pub fn get_sequence_number(&self) -> u32 {
        let i = self.get_ip_header_len() * 4;
        u32::from_be_bytes([self.byte_arr[i + 4], self.byte_arr[i + 5], self.byte_arr[i + 6], self.byte_arr[i + 7]])
    }

    /// 获取ack码
    pub fn get_acknowledgment_number(&self) -> u32 {
        let i = self.get_ip_header_len() * 4;
        u32::from_be_bytes([self.byte_arr[i + 8], self.byte_arr[i + 9], self.byte_arr[i + 10], self.byte_arr[i + 11]])
    }

    /// 获取TCP数据包头长度，总字节 = 首部长度 * 4
    pub fn get_tcp_header_len(&self) -> u8 {
        let i = self.get_ip_header_len() * 4;
        self.byte_arr[i + 12] >> 4
    }

    pub fn is_ack(&self) -> bool {
        let i = self.get_ip_header_len() * 4;
        self.byte_arr[i + 13] & 0b00010000 == 0b00010000
    }
    pub fn is_psh(&self) -> bool {
        let i = self.get_ip_header_len() * 4;
        self.byte_arr[i + 13] & 0b00001000 == 0b00001000
    }
    pub fn is_rst(&self) -> bool {
        let i = self.get_ip_header_len() * 4;
        self.byte_arr[i + 13] & 0b00000100 == 0b00000100
    }
    pub fn is_syn(&self) -> bool {
        let i = self.get_ip_header_len() * 4;
        self.byte_arr[i + 13] & 0b00000010 == 0b00000010
    }
    pub fn is_fin(&self) -> bool {
        let i = self.get_ip_header_len() * 4;
        self.byte_arr[i + 13] & 0b00000001 == 0b00000001
    }

    /// 获取数据包校验和
    pub fn get_checksum(&self) -> u16 {
        let i = self.get_ip_header_len() * 4;
        match self.get_protocol() {
            Protocol::ICMP => { 0 }
            Protocol::TCP => {
                eprintln!("{:x?}", [self.byte_arr[i + 16], self.byte_arr[i + 17]]);
                u16::from_be_bytes([self.byte_arr[i + 16], self.byte_arr[i + 17]])
            }
            Protocol::UDP => {
                u16::from_be_bytes([self.byte_arr[i + 6], self.byte_arr[i + 7]])
            }
            Protocol::Unknown => { 0 }
        }
    }

    /// 获取数据包数据
    pub fn get_data(&self) -> &[u8] {
        let i = self.get_ip_header_len() * 4;
        match self.get_protocol() {
            Protocol::ICMP => { &[] }
            Protocol::TCP => {
                // let udp_len = u16::from_be_bytes([self.byte_arr[i + 4], self.byte_arr[i + 5]]);
                // let tcp_header_len= u16::from_be_bytes()
                &self.byte_arr[0..0]
            }
            Protocol::UDP => {
                let udp_len = u16::from_be_bytes([self.byte_arr[i + 4], self.byte_arr[i + 5]]);
                &self.byte_arr[i + 8..(i + udp_len as usize)]
            }
            Protocol::Unknown => { &[] }
        }
    }
}

#[test]
fn main() {
    let hex_string = "45900468f65040003006f41a2ff20674c0a864861771ca21471b87b3ddbac2b5501809c9073f0000";

    // 解析十六进制字符串为字节数组
    let bytes = hex::decode(hex_string).expect("Failed to decode hex string");


    let packet = Packet::from_byte(bytes.as_slice());
    println!("{:?}", packet.get_version());
    println!("{}", packet.get_ip_header_len());
    println!("{:?}", packet.get_protocol());
    println!("{}", packet.get_source_addr());
    println!("{}", packet.get_target_addr());
    println!("{}", packet.get_source_port());
    println!("{}", packet.get_target_port());
    println!("{}", packet.get_sequence_number());
    println!("{}", packet.get_acknowledgment_number());
    println!("{}", packet.get_checksum());
    println!("{}", packet.get_total_len());
    println!("{}", packet.get_ip_checksum());
    println!("{}", packet.get_tcp_header_len());
    println!("is_ack {}", packet.is_ack());
    println!("is_psh {}", packet.is_psh());
    println!("is_rst {}", packet.is_rst());
    println!("is_syn {}", packet.is_syn());
    println!("is_fin {}", packet.is_fin());
    crate::tun::tun_handler::print(packet.get_data());
}