use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Prefix;


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

pub struct Packet {
    byte_arr: Vec<u8>,
}

impl Packet {
    pub fn from_byte(byte: Vec<u8>) -> Packet {
        Packet {
            byte_arr: byte,
        }
    }

    pub fn build_tcp_packet(
        id: u32,
        source_addr: Ipv4Addr,
        target_addr: Ipv4Addr,
        source_port: u16,
        target_port: u16,
        data: Option<Vec<u8>>,
    ) -> Packet {
        let data_len = if data.is_none() { 0 } else { data.as_ref().unwrap().len() };
        let mut byte_arr = Vec::<u8>::new();
        // version
        byte_arr.push(0x45);
        byte_arr.push(0x00);
        // total len
        let total_len = 40 + data_len;
        byte_arr.push((total_len >> 8) as u8);
        byte_arr.push((total_len & 0xff) as u8);
        // id
        byte_arr.push((id >> 8) as u8);
        byte_arr.push((id & 0xff) as u8);
        // fragment flag
        byte_arr.push(0x40);
        byte_arr.push(0x00);
        // live
        byte_arr.push(0x80);
        // protocol
        byte_arr.push(0x06);
        // checksum
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        // source addr
        let source_addr_byte = source_addr.octets();
        byte_arr.push(source_addr_byte[0]);
        byte_arr.push(source_addr_byte[1]);
        byte_arr.push(source_addr_byte[2]);
        byte_arr.push(source_addr_byte[3]);
        // target addr
        let target_addr_byte = target_addr.octets();
        byte_arr.push(target_addr_byte[0]);
        byte_arr.push(target_addr_byte[1]);
        byte_arr.push(target_addr_byte[2]);
        byte_arr.push(target_addr_byte[3]);
        // source port
        byte_arr.push((source_port >> 8) as u8);
        byte_arr.push((source_port & 0xff) as u8);
        // target port
        byte_arr.push((target_port >> 8) as u8);
        byte_arr.push((target_port & 0xff) as u8);
        // sequence number
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        // acknowledgment number
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        // tcp header len 固定20
        byte_arr.push(0x50);
        byte_arr.push(0x00);
        // window
        byte_arr.push(0xff);
        byte_arr.push(0xff);
        // checksum
        byte_arr.push(0x00);
        byte_arr.push(0x00);
        // pointer
        byte_arr.push(0x00);
        byte_arr.push(0x00);

        if let Some(mut d) = data {
            byte_arr.append(&mut d);
        }

        Packet {
            byte_arr
        }
    }
}

impl Packet {
    /// 获取IP数据包总长
    pub fn get_total_len(&self) -> i32 {
        if self.byte_arr.len() < 4 {
            return -1;
        }
        match self.get_version() {
            Version::IPV4 => {
                u16::from_be_bytes([self.byte_arr[2], self.byte_arr[3]]) as i32
            }
            Version::IPV6 => {
                u16::from_be_bytes([self.byte_arr[4], self.byte_arr[5]]) as i32 + 40
            }
            Version::Unknown => { -1 }
        }
    }

    pub fn set_identification(&mut self, id: u32) {
        self.byte_arr[4] = (id >> 8) as u8;
        self.byte_arr[5] = (id & 0x00ff) as u8;
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
        (self.byte_arr[0] & 0x0f) as usize * 4
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
        u16::from_be_bytes([self.byte_arr[10], self.byte_arr[11]])
    }

    /// 计算ip数据包校验和
    pub fn calculate_ip_checksum(&mut self) {
        let len = self.get_ip_header_len();

        self.byte_arr[10] = 0;
        self.byte_arr[11] = 0;

        let mut sum: u32 = 0;
        for i in (0..len).step_by(2) {
            let word = u16::from_be_bytes([self.byte_arr[i], self.byte_arr[i + 1]]);
            sum = sum.wrapping_add(u32::from(word));
        }

        // If the length is odd, add the last byte
        if self.byte_arr.len() % 2 == 1 {
            let last_byte = u16::from_be_bytes([self.byte_arr[self.byte_arr.len() - 1], 0]);
            sum = sum.wrapping_add(u32::from(last_byte));
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // Take the one's complement
        let checksum = !sum as u16;

        self.byte_arr[10] = (checksum >> 8) as u8;
        self.byte_arr[11] = (checksum & 0x00ff) as u8;
    }

    /// 获取源地址
    pub fn get_source_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([self.byte_arr[12], self.byte_arr[13], self.byte_arr[14], self.byte_arr[15]])
    }

    /// 设置源地址
    pub fn set_source_addr(&mut self, ipv4addr: &Ipv4Addr) {
        let x = ipv4addr.octets();
        self.byte_arr[12] = x[0];
        self.byte_arr[13] = x[1];
        self.byte_arr[14] = x[2];
        self.byte_arr[15] = x[3];
    }

    /// 获取目标地址
    pub fn get_target_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from([self.byte_arr[16], self.byte_arr[17], self.byte_arr[18], self.byte_arr[19]])
    }

    /// 设置目标地址
    pub fn set_target_addr(&mut self, ipv4addr: &Ipv4Addr) {
        let x = ipv4addr.octets();
        self.byte_arr[16] = x[0];
        self.byte_arr[17] = x[1];
        self.byte_arr[18] = x[2];
        self.byte_arr[19] = x[3];
    }
    /// 获取源端口
    pub fn get_source_port(&self) -> u16 {
        let i = self.get_ip_header_len();
        u16::from_be_bytes([self.byte_arr[i], self.byte_arr[i + 1]])
    }

    /// 设置源端口
    pub fn set_source_port(&mut self, port: u16) {
        let x = port.to_be_bytes();
        let i = self.get_ip_header_len();
        self.byte_arr[i] = x[0];
        self.byte_arr[i + 1] = x[1];
    }

    /// 获取目标端口
    pub fn get_target_port(&self) -> u16 {
        let i = self.get_ip_header_len();
        u16::from_be_bytes([self.byte_arr[i + 2], self.byte_arr[i + 3]])
    }

    /// 设置目标端口
    pub fn set_target_port(&mut self, port: u16) {
        let x = port.to_be_bytes();
        let i = self.get_ip_header_len();
        self.byte_arr[i + 2] = x[0];
        self.byte_arr[i + 3] = x[1];
    }
    /// 获取seq码
    pub fn get_sequence_number(&self) -> u32 {
        let i = self.get_ip_header_len();
        u32::from_be_bytes([self.byte_arr[i + 4], self.byte_arr[i + 5], self.byte_arr[i + 6], self.byte_arr[i + 7]])
    }

    /// 设置seq码
    pub fn set_sequence_number(&mut self, num: u32) {
        let x = num.to_be_bytes();
        let i = self.get_ip_header_len();
        self.byte_arr[i + 4] = x[0];
        self.byte_arr[i + 5] = x[1];
        self.byte_arr[i + 6] = x[2];
        self.byte_arr[i + 7] = x[3];
    }

    /// 获取ack码
    pub fn get_acknowledgment_number(&self) -> u32 {
        let i = self.get_ip_header_len();
        u32::from_be_bytes([self.byte_arr[i + 8], self.byte_arr[i + 9], self.byte_arr[i + 10], self.byte_arr[i + 11]])
    }

    /// 设置ack码
    pub fn set_acknowledgment_number(&mut self, num: u32) {
        let x = num.to_be_bytes();
        let i = self.get_ip_header_len();
        self.byte_arr[i + 8] = x[0];
        self.byte_arr[i + 9] = x[1];
        self.byte_arr[i + 10] = x[2];
        self.byte_arr[i + 11] = x[3];
    }

    /// 获取TCP数据包头长度，总字节 = 首部长度 * 4
    pub fn get_tcp_header_len(&self) -> u8 {
        let i = self.get_ip_header_len();
        (self.byte_arr[i + 12] >> 4) * 4
    }

    pub fn is_ack(&self) -> bool {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] & 0b00010000 == 0b00010000
    }

    pub fn set_ack(&mut self) {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] |= 0b00010000
    }

    pub fn is_psh(&self) -> bool {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] & 0b00001000 == 0b00001000
    }

    pub fn set_psh(&mut self) {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] |= 0b00001000;
    }

    pub fn is_rst(&self) -> bool {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] & 0b00000100 == 0b00000100
    }

    pub fn set_rst(&mut self) {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] |= 0b00000100;
    }

    pub fn is_syn(&self) -> bool {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] & 0b00000010 == 0b00000010
    }

    pub fn set_syn(&mut self) {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] |= 0b00000010;
    }

    pub fn is_fin(&self) -> bool {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] & 0b00000001 == 0b00000001
    }

    pub fn set_fin(&mut self) {
        let i = self.get_ip_header_len();
        self.byte_arr[i + 13] |= 0b00000001;
    }

    /// 获取数据包校验和
    pub fn get_checksum(&self) -> u16 {
        let i = self.get_ip_header_len();
        match self.get_protocol() {
            Protocol::ICMP => { 0 }
            Protocol::TCP => {
                u16::from_be_bytes([self.byte_arr[i + 16], self.byte_arr[i + 17]])
            }
            Protocol::UDP => {
                u16::from_be_bytes([self.byte_arr[i + 6], self.byte_arr[i + 7]])
            }
            Protocol::Unknown => { 0 }
        }
    }

    /// 计算校验和
    pub fn calculate_checksum(&mut self) {
        let i = self.get_ip_header_len();
        match self.get_protocol() {
            Protocol::ICMP => {}
            Protocol::TCP => {
                let end = self.get_total_len() as usize;

                self.byte_arr[i + 16] = 0;
                self.byte_arr[i + 17] = 0;

                let mut sum: u32 = 0;
                {
                    let word = u16::from_be_bytes([0x00, 0x06]) as u32;
                    sum = sum.wrapping_add(word);
                }
                {
                    sum = sum.wrapping_add(u32::from((self.get_total_len() - self.get_ip_header_len() as i32) as u32));
                }
                let checksum_len = if end % 2 == 1 {
                    end - 1
                } else { end };
                for i in (i - 8..checksum_len).step_by(2) {
                    let word = u16::from_be_bytes([self.byte_arr[i], self.byte_arr[i + 1]]) as u32;
                    sum = sum.wrapping_add(word);
                }

                // If the length is odd, add the last byte
                if end % 2 == 1 {
                    let last_byte = u16::from_be_bytes([self.byte_arr[self.byte_arr.len() - 1], 0]) as u32;
                    sum = sum.wrapping_add(last_byte);
                }

                // Fold 32-bit sum to 16 bits
                while (sum >> 16) > 0 {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }

                // Take the one's complement
                let checksum = !sum as u16;

                self.byte_arr[i + 16] = (checksum >> 8) as u8;
                self.byte_arr[i + 17] = (checksum & 0xff) as u8;
            }
            Protocol::UDP => {
                // UDP不校验
                self.byte_arr[i + 6] = 0;
                self.byte_arr[i + 7] = 0;
            }
            Protocol::Unknown => {}
        }
    }

    /// 获取数据包数据
    pub fn get_data(&self) -> &[u8] {
        let i = self.get_ip_header_len();
        match self.get_protocol() {
            Protocol::ICMP => { &[] }
            Protocol::TCP => {
                let end = self.get_total_len() as usize;
                let start = self.get_ip_header_len() + self.get_tcp_header_len() as usize;
                &self.byte_arr[start..end]
            }
            Protocol::UDP => {
                let udp_len = u16::from_be_bytes([self.byte_arr[i + 4], self.byte_arr[i + 5]]);
                &self.byte_arr[i + 8..(i + udp_len as usize)]
            }
            Protocol::Unknown => { &[] }
        }
    }

    pub fn to_byte(&self) -> Vec<u8> {
        self.byte_arr[0..self.get_total_len() as usize].to_vec()
    }
}

#[tokio::test]
async fn main() {
    // let hex_string = "45000040000000004006108ec0a864862ff2150ac5f6ff98c2c80cc500000000b002ffff39d00000020405b4010303060101080a2646d79d0000000004020000";
    //
    // // 解析十六进制字符串为字节数组
    // let bytes = hex::decode(hex_string).expect("Failed to decode hex string");
    //
    //
    // let mut packet = Packet::from_byte(bytes);
    // println!("get_version {:?}", packet.get_version());
    // println!("get_ip_header_len {}", packet.get_ip_header_len());
    // println!("get_protocol {:?}", packet.get_protocol());
    // println!("get_source_addr {}", packet.get_source_addr());
    // println!("get_target_addr {}", packet.get_target_addr());
    // println!("get_source_port {}", packet.get_source_port());
    // println!("get_target_port {}", packet.get_target_port());
    // println!("get_sequence_number {}", packet.get_sequence_number());
    // println!("get_acknowledgment_number {}", packet.get_acknowledgment_number());
    // println!("get_checksum {}", packet.get_checksum());
    // println!("get_checksum {}", packet.get_checksum());
    // println!("get_total_len {}", packet.get_total_len());
    // println!("get_ip_checksum {}", packet.get_ip_checksum());
    // println!("get_ip_checksum {}", packet.get_ip_checksum());
    // println!("get_tcp_header_len {}", packet.get_tcp_header_len());
    // println!("is_ack {}", packet.is_ack());
    // println!("is_psh {}", packet.is_psh());
    // println!("is_rst {}", packet.is_rst());
    // println!("is_syn {}", packet.is_syn());
    // println!("is_fin {}", packet.is_fin());
    // print(packet.get_data());
    //
    // let tcp_pipe_context = TcpPipeContext::new();
    // if packet.is_syn() {
    //     if let Some(tcp_pipe) = tcp_pipe_context.create_pipe(&packet).await {
    //         let vec = tcp_pipe.read().await.do_ack_syn(&mut packet);
    //         eprintln!("do syn,data:{:?}", packet.get_data());
    //         print(vec.as_slice());
    //     }
    // }
    //
    // let hex_string = "450001010000000040060fcdc0a864862ff2150ac5f6ff98c2c80cc647ee1c508018080c660b00000101080a2646d7ade37308b6474554202f20485454502f312e310d0a557365722d4167656e743a20506f73746d616e52756e74696d652f372e33322e330d0a4163636570743a202a2f2a0d0a506f73746d616e2d546f6b656e3a2065366161356536652d323766382d346562612d383135342d3265366364306235663633660d0a486f73743a2034372e3234322e32312e31303a36353433320d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174652c2062720d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a0d0a";
    // // 解析十六进制字符串为字节数组
    // let bytes = hex::decode(hex_string).expect("Failed to decode hex string");
    // let mut packet = Packet::from_byte(bytes);
    //
    // if packet.is_psh() {
    //     if let Some(mut pipe) = tcp_pipe_context.get_pipe(&packet).await {
    //         let vec = pipe.write().await.do_ack_psh(&mut packet);
    //         eprintln!("do ack psh");
    //         print(vec.as_slice());
    //     }
    // }
    //
    // if let Some(mut pipe) = tcp_pipe_context.get_pipe(&packet).await {
    //     let hex_string = "485454502f312e3120323030200d0a566172793a204f726967696e0d0a566172793a204163636573732d436f6e74726f6c2d526571756573742d4d6574686f640d0a566172793a204163636573732d436f6e74726f6c2d526571756573742d486561646572730d0a4c6173742d4d6f6469666965643a205468752c2031372041756720323032332030383a31313a313020474d540d0a4163636570742d52616e6765733a2062797465730d0a436f6e74656e742d547970653a20746578742f68746d6c3b636861727365743d5554462d380d0a436f6e74656e742d4c616e67756167653a20656e2d55530d0a436f6e74656e742d4c656e6774683a20353632310d0a446174653a204672692c203035204a616e20323032342031343a30363a303620474d540d0a4b6565702d416c6976653a2074696d656f75743d36300d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a0d0a3c21444f43545950452068746d6c3e3c68746d6c3e3c686561643e3c6d65746120636861727365743d7574662d383e3c6d65746120687474702d65717569763d582d55412d436f6d70617469626c6520636f6e74656e743d2249453d656467652c6368726f6d653d31223e3c6d657461206e616d653d726f626f747320636f6e74656e743d6e6f6e653e3c6d657461206e616d653d76696577706f727420636f6e74656e743d2277696474683d6465766963652d77696474682c696e697469616c2d7363616c653d312c6d6178696d756d2d7363616c653d312c757365722d7363616c61626c653d6e6f223e3c6c696e6b2072656c3d69636f6e20687265663d2f66617669636f6e2e706e673e3c7469746c653ee997b2e89b8be4b8ade8bdac3c2f7469746c653e3c6c696e6b20687265663d2f7374617469632f6373732f6170702e39643062613635612e6373732072656c3d7072656c6f61642061733d7374796c653e3c6c696e6b20687265663d2f7374617469632f6373732f6368756e6b2d656c656d656e7455492e36386337306164352e6373732072656c3d7072656c6f61642061733d7374796c653e3c6c696e6b20687265663d2f7374617469632f6373732f6368756e6b2d6c6962732e33646662373736392e6373732072656c3d7072656c6f61642061733d7374796c653e3c6c696e6b20687265663d2f7374617469632f6a732f6170702e32666133336531392e6a732072656c3d7072656c6f61642061733d7363726970743e3c6c696e6b20687265663d2f7374617469632f6a732f6368756e6b2d656c656d656e7455492e39323731323739632e6a732072656c3d7072656c6f61642061733d7363726970743e3c6c696e6b20687265663d2f7374617469632f6a732f6368756e6b2d6c6962732e62326136373037322e6a732072656c3d7072656c6f61642061733d7363726970743e3c6c696e6b20687265663d2f7374617469632f6373732f6368756e6b2d656c656d656e7455492e36386337306164352e6373732072656c3d7374796c6573686565743e3c6c696e6b20687265663d2f7374617469632f6373732f6368756e6b2d6c6962732e33646662373736392e6373732072656c3d7374796c6573686565743e3c6c696e6b20687265663d2f7374617469632f6373732f6170702e39643062613635612e6373732072656c3d7374796c6573686565743e3c2f686561643e3c626f64793e3c6e6f7363726970743e3c7374726f6e673e576527726520736f7272792062757420e997b2e89b8be4b8ade8bdac20646f65736e277420776f726b2070726f7065726c7920776974686f7574204a61766153637269707420656e61626c65642e20506c6561736520656e61626c6520697420746f20636f6e74696e75652e3c2f7374726f6e673e3c2f6e6f7363726970743e3c6469762069643d6170703e3c2f6469763e3c7363726970743e2866756e637469";
    //     // 解析十六进制字符串为字节数组
    //     let bytes = hex::decode(hex_string).expect("Failed to decode hex string");
    //     let vec = pipe.write().await.do_psh(bytes);
    //     eprintln!("do psh");
    //     print(vec.as_slice());
    // }
}

pub(crate) fn print(prefix: &str,bytes: &[u8]) {
    // for byte in bytes {
    //     print!("{:02x} ", byte);
    // }
    // println!();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open
        ("C:/Users/ljc/Downloads/rust_file").unwrap();

    let _ = file.write_all(prefix.as_bytes());
    let _ = file.write_all(" 00000000 ".as_bytes());
    for byte in bytes {
        let _ = file.write_all(format!("{:02x} ", byte).as_bytes());
    }
    let _ = file.write_all("\n".as_bytes());
}