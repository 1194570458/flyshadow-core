use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::sync::mpsc::{Receiver, Sender};

use crate::context::context::TunnelContext;

pub async fn handle(header_data: Vec<u8>,
                    client_sender: Sender<Vec<u8>>,
                    client_receiver: Receiver<Vec<u8>>,
                    source_addr: String,
                    context: Arc<TunnelContext>) -> String {
    let header_data_len = header_data.len();
    let command = header_data[1];
    let address_type = header_data[3];

    let domain = match address_type {
        // IPV4
        0x01 => {
            Ipv4Addr::new(
                header_data[4], header_data[5], header_data[6], header_data[7],
            ).to_string()
        }
        // Domain
        0x03 => {
            let len = header_data[4];
            let mut data = Vec::<u8>::new();
            for i in 0..len {
                data.push(header_data[(i + 5) as usize]);
            }
            String::from_utf8_lossy(data.as_slice()).to_string()
        }
        // IPV6
        0x04 => {
            let mut data = [0u8; 16];
            for i in 0..16 {
                data[i] = header_data[i + 4];
            }
            Ipv6Addr::from(data).to_string()
        }
        _ => { "".to_string() }
    };

    let port = (((header_data[header_data_len - 2] & 0xff) as i32) << 8) | ((header_data[header_data_len - 1] & 0xff) as i32);

    // TCP
    if command == 0x01 {
        // 响应TCP连接
        let _ = client_sender.send(vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await;
    }
    // UDP
    else if command == 0x03 {}

    return "".to_string();
}