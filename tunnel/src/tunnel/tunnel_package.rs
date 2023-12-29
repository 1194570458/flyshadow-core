
/// 隧道数据包
#[derive(Debug)]
pub struct TunnelPackage {
    pub cmd: PackageCmd,
    pub protocol: PackageProtocol,
    pub source_address: Option<String>,
    pub target_address: Option<String>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum PackageProtocol {
    TCP = 0x01,
    UDP = 0x02,
    NONE,
}

impl PackageProtocol {
    fn from_protocol(protocol: u8) -> PackageProtocol {
        match protocol {
            0x01 => { PackageProtocol::TCP }
            0x02 => { PackageProtocol::UDP }
            _ => { PackageProtocol::NONE }
        }
    }

    fn as_byte(&self) -> u8 {
        match self {
            PackageProtocol::TCP => { 0x01 }
            PackageProtocol::UDP => { 0x02 }
            PackageProtocol::NONE => { 0xf0 }
        }
    }
}

#[derive(Debug)]
pub enum PackageCmd {
    Login = 0x01,
    NewConnect = 0x03,
    CloseConnect = 0x04,
    TData = 0x05,
    PING = 0x06,
    LoginSuccess = 0x41,
    LoginFail = 0x42,
    ProtocolError = 0x43,
    PONG = 0x44,
    NONE,
}

impl PackageCmd {
    fn from_cmd(cmd: u8) -> PackageCmd {
        match cmd {
            0x01 => { PackageCmd::Login }
            0x03 => { PackageCmd::NewConnect }
            0x04 => { PackageCmd::CloseConnect }
            0x05 => { PackageCmd::TData }
            0x06 => { PackageCmd::PING }
            0x41 => { PackageCmd::LoginSuccess }
            0x42 => { PackageCmd::LoginFail }
            0x43 => { PackageCmd::ProtocolError }
            0x44 => { PackageCmd::PONG }
            _ => { PackageCmd::NONE }
        }
    }

    fn as_byte(&self) -> u8 {
        match self {
            PackageCmd::Login => { 0x01 }
            PackageCmd::NewConnect => { 0x03 }
            PackageCmd::CloseConnect => { 0x04 }
            PackageCmd::TData => { 0x05 }
            PackageCmd::PING => { 0x06 }
            PackageCmd::NONE => { 0xf0 }
            PackageCmd::LoginSuccess => { 0x41 }
            PackageCmd::LoginFail => { 0x42 }
            PackageCmd::ProtocolError => { 0x43 }
            PackageCmd::PONG => { 0x44 }
        }
    }
}

impl TunnelPackage {
    pub fn new(cmd: PackageCmd, protocol: PackageProtocol, source_address: Option<String>, target_address: Option<String>, data: Option<Vec<u8>>) -> TunnelPackage {
        TunnelPackage {
            cmd,
            protocol,
            source_address,
            target_address,
            data,
        }
    }
}

impl TunnelPackage {
    pub fn to_byte_array(&mut self, vec: &mut Vec<u8>) {
        vec.push(0x0f);
        vec.push(0x2f);
        vec.push(self.cmd.as_byte());
        vec.push(self.protocol.as_byte());

        let source_addr = self.source_address.take();
        match source_addr {
            None => {
                vec.push(0u8);
                vec.push(0u8);
                vec.push(0u8);
                vec.push(0u8);
            }
            Some(addr) => {
                vec.append(&mut (addr.len() as u32).to_le_bytes().to_vec());
                vec.append(&mut addr.as_bytes().to_vec());
            }
        }

        let target_addr = self.target_address.take();
        match target_addr {
            None => {
                vec.push(0u8);
                vec.push(0u8);
                vec.push(0u8);
                vec.push(0u8);
            }
            Some(addr) => {
                vec.append(&mut (addr.len() as u32).to_le_bytes().to_vec());
                vec.append(&mut addr.as_bytes().to_vec());
            }
        }

        let data = self.data.take();
        match data {
            None => {
                vec.push(0u8);
                vec.push(0u8);
                vec.push(0u8);
                vec.push(0u8);
            }
            Some(mut data) => {
                let mut vec1 = (data.len() as u32).to_le_bytes().to_vec();
                vec.append(&mut vec1);
                vec.append(&mut data);
            }
        }
    }

    pub fn from_byte_array(data: &[u8]) -> TunnelPackage {
        let mut index = 0;

        let _header1 = data[index];
        index += 1;
        let _header2 = data[index];
        index += 1;
        let cmd = PackageCmd::from_cmd(data[index]);
        index += 1;
        let protocol = PackageProtocol::from_protocol(data[index]);
        index += 1;

        let source_address_len = u32::from_le_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
        index += 4;
        let source_address = if source_address_len == 0 { None } else {
            let source_addr_str = Some(String::from_utf8_lossy(&data[index..index + source_address_len as usize]).to_string());
            index += source_address_len as usize;
            source_addr_str
        };
        let target_address_len = u32::from_le_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
        index += 4;
        let target_address = if target_address_len == 0 { None } else {
            let target_addr_str = Some(String::from_utf8_lossy(&data[index..index + target_address_len as usize]).to_string());
            index += target_address_len as usize;
            target_addr_str
        };

        let data_len = u32::from_le_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]]);
        index += 4;

        return TunnelPackage {
            cmd,
            protocol,
            source_address,
            target_address,
            data: if data_len != 0 { Some(data[index..(index + data_len as usize)].to_vec()) } else { None },
        };
    }
}