use std::net::Ipv4Addr;
use serde::__private::de::Content::U8;

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

    pub fn get_version(&self) -> Version {
        match self.byte_arr[0] >> 4 {
            4 => { Version::IPV4 }
            6 => { Version::IPV6 }
            _ => { Version::Unknown }
        }
    }
    /// 首部长度 *4 总字节
    pub fn get_ip_header_len(&self) -> usize {
        (self.byte_arr[0] & 0x0f) as usize
    }
    pub fn get_protocol(&self) -> Protocol {
        match self.byte_arr[9] {
            1 => { Protocol::ICMP }
            6 => { Protocol::TCP }
            17 => { Protocol::UDP }
            _ => { Protocol::Unknown }
        }
    }

    pub fn get_source_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([self.byte_arr[12], self.byte_arr[13], self.byte_arr[14], self.byte_arr[15]])
    }

    pub fn get_target_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([self.byte_arr[16], self.byte_arr[17], self.byte_arr[18], self.byte_arr[19]])
    }

    pub fn get_source_port(&self) -> u16 {
        let i = self.get_ip_header_len() * 4;
        u16::from_be_bytes([self.byte_arr[i], self.byte_arr[i + 1]])
    }

    pub fn get_target_port(&self) -> u16 {
        let i = self.get_ip_header_len() * 4;
        u16::from_be_bytes([self.byte_arr[i + 2], self.byte_arr[i + 3]])
    }


    pub fn get_sequence_number(&self) -> u32 {
        let i = self.get_ip_header_len() * 4;
        u32::from_be_bytes([self.byte_arr[i + 4], self.byte_arr[i + 5], self.byte_arr[i + 6], self.byte_arr[i + 7]])
    }

    pub fn get_acknowledgment_number(&self)->u32{
        let i = self.get_ip_header_len() * 4;
        u32::from_be_bytes([self.byte_arr[i + 8], self.byte_arr[i + 9], self.byte_arr[i + 10], self.byte_arr[i + 11]])
    }

    pub fn get_checksum(&self)->u16{
        let i = self.get_ip_header_len() * 4;
        match self.get_protocol() {
            Protocol::ICMP => {0}
            Protocol::TCP => {
                eprintln!("{:x?}",[self.byte_arr[i + 16], self.byte_arr[i + 17]]);
                u16::from_be_bytes([self.byte_arr[i + 16], self.byte_arr[i + 17]])
            }
            Protocol::UDP => {
                u16::from_be_bytes([self.byte_arr[i + 6], self.byte_arr[i + 7]])
            }
            Protocol::Unknown => {0}
        }
    }
    pub fn get_data(&self) -> &[u8] {
        let i = self.get_ip_header_len() * 4;
        match self.get_protocol() {
            Protocol::ICMP => { &[] }
            Protocol::TCP => {
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
    let packet = Packet::from_byte(&[0x45,0x00,0x00,0x3c,0x0a,0x3c,0x40,0x00,0x40,0x06,0xae,0xd6,0x0a,0xac,0x32,0x02,0x2f,0xf2,0x15,0x0a,0x93,0xf8,0xff,0x98,0xbb,0x90,0xc5,0x89,0x00,0x00,0x00,0x00,0xa0,0x02,0xfa,0xf0,0xda,0xce,0x00,0x00,0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,0x78,0xdc,0x63,0x0e,0x00,0x00,0x00,0x00,0x01,0x03,0x03,0x07,0x45,0x00,0x00,0x40,0x91,0x9b,0x40,0x00,0x40,0x11,0x6a,0x62,0x0a,0xac,0x32,0x02,0x01,0x01,0x01,0x01,0x94,0x4c,0x00,0x35,0x00,0x2c,0x1c,0x71,0x99,0x81,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x77,0x77,0x77,0x0a,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x61,0x70,0x69,0x73,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01]);
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
    crate::tun::tun_handler::print(packet.get_data());
}