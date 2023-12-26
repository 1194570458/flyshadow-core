use std::io::Error;
use std::sync::Arc;

use crypto::{aes, buffer};
use crypto::aes::KeySize;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::md5::Md5;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, Mutex};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

/// 隧道结构体
pub struct Tunnel {
    // 隧道地址
    host: String,
    port: u16,
    // 隧道用户信息
    password: String,
    // 隧道流量信息
    upload: Arc<Mutex<i64>>,
    download: Arc<Mutex<i64>>,
    // 外部的 tunnel package发送着和接收着
    sender: Sender<TunnelPackage>,
    tunnel_package_receiver: Option<Receiver<TunnelPackage>>,
    // 隧道的发送着和接收着
    tx: Option<Sender<TunnelPackage>>,
    rx: Option<Receiver<TunnelPackage>>,
    close_sender: broadcast::Sender<u8>,
}

unsafe impl Send for Tunnel {}

impl Tunnel {
    pub fn new(host: String, port: u16, password: String) -> Tunnel {
        // 消息接收和发送
        let (tx, receiver) = channel::<TunnelPackage>(1024);
        let (sender, rx) = channel::<TunnelPackage>(1024);

        // 关闭的消息发送和接收
        let (close_sender, _close_receiver) = broadcast::channel::<u8>(16);

        Tunnel {
            host,
            port,
            password,
            upload: Arc::new(Mutex::new(0)),
            download: Arc::new(Mutex::new(0)),
            sender,
            tunnel_package_receiver: Some(receiver),
            tx: Some(tx),
            rx: Some(rx),
            close_sender,
        }
    }
    /// 连接隧道
    pub async fn connect(&mut self) -> Result<(), Error> {
        let host = &self.host[..];
        let port = self.port;
        let password = &self.password[..];

        let rx = self.rx.take().unwrap();
        let tx = self.tx.take().unwrap();

        match TcpStream::connect((host, port)).await {
            Ok(tcp_stream) => {
                let (reader, writer) = tcp_stream.into_split();

                let close_sender1 = self.close_sender.clone();
                let close_sender2 = self.close_sender.clone();


                // 加密解密密钥
                let mut hasher = Md5::new();
                hasher.input_str(password);
                let md5_pwd = hasher.result_str();
                let md5_password = Arc::new(md5_pwd.clone());
                let pwd1 = md5_password.clone();
                let pwd2 = md5_password.clone();

                let _ = self.sender.send(TunnelPackage::new(PackageCmd::Login, PackageProtocol::TCP, None, None, Some(md5_pwd.clone().into_bytes())));

                // 写消息线程
                let write_handler = tokio::spawn(async move {
                    Self::write_to_tunnel(writer, rx, pwd1.as_bytes(), close_sender1).await;
                });

                // 读消息线程
                let read_handler = tokio::spawn(async move {
                    Self::read_from_tunnel(reader, tx, pwd2.as_bytes(), close_sender2).await;
                });

                let _ = self.close_receiver().recv().await;
                write_handler.abort();
                read_handler.abort();
                eprintln!("write&read handler abort");

                Ok(())
            }
            Err(e) => { Err(e) }
        }
    }

    /// 数据包获取接收者
    pub fn tunnel_package_receiver(&mut self) -> Option<Receiver<TunnelPackage>> {
        self.tunnel_package_receiver.take()
    }

    /// 关闭消息的接收者
    pub fn close_receiver(&self) -> broadcast::Receiver<u8> {
        self.close_sender.subscribe()
    }

    /// 断开连接
    pub fn disconnect(&self) {
        let _ = self.close_sender.send(0);
    }

    /// 写消息
    pub fn write_tunnel_package(&self, tunnel_package: TunnelPackage) {
        let _ = self.sender.send(tunnel_package);
    }

    pub fn get_sender(&self) -> Sender<TunnelPackage> {
        self.sender.clone()
    }


    /// 从tcp读取数据
    async fn read_from_tunnel(mut reader: OwnedReadHalf, sender: Sender<TunnelPackage>, pwd: &[u8], close_sender: broadcast::Sender<u8>) {
        let mut buffer_tmp: Vec<u8> = Vec::new();
        let mut data = [0; 4096];

        loop {
            match reader.read(&mut data).await {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    buffer_tmp.append(&mut data[..n].to_vec());

                    if buffer_tmp[0] != 0x0f && buffer_tmp[1] != 0x2f {
                        break;
                    }

                    if buffer_tmp.len() < 6 {
                        continue;
                    }

                    let data_length = i32::from_be_bytes([buffer_tmp[2], buffer_tmp[3], buffer_tmp[4], buffer_tmp[5]]);
                    if buffer_tmp.len() < data_length as usize {
                        continue;
                    }
                    // eprintln!("read package:{:02x?}", buffer_tmp);

                    let mut new_buffer = buffer_tmp.split_off((data_length + 6) as usize);
                    let read_data_arr = &buffer_tmp.as_slice()[6..];

                    // eprintln!("read decryptor:{:02x?}", read_data_arr);
                    // 解密
                    let mut final_result = Vec::<u8>::new();
                    let mut read_buffer = buffer::RefReadBuffer::new(read_data_arr);
                    let mut buffer = [0; 4096];
                    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

                    {
                        let mut decryptor = aes::ecb_decryptor(KeySize::KeySize256, pwd, PkcsPadding);
                        loop {
                            let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
                            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
                            match result {
                                BufferResult::BufferUnderflow => break,
                                BufferResult::BufferOverflow => {}
                            }
                        }
                    }

                    // 转成结构体
                    let tunnel_package = TunnelPackage::from_byte_array(final_result.as_slice());
                    // eprintln!("read package: {:?}", tunnel_package);
                    if let Err(_) = sender.send(tunnel_package).await {
                        break;
                    }
                    buffer_tmp.clear();
                    buffer_tmp.append(&mut new_buffer);
                }
                Err(_) => { break; }
            }
        }
        let _ = close_sender.send(1);
    }

    /// 写隧道数据包到tcp上
    async fn write_to_tunnel(mut writer: OwnedWriteHalf, mut receiver: Receiver<TunnelPackage>, pwd: &[u8], close_sender: broadcast::Sender<u8>) {
        while let Some(mut package) = receiver.recv().await {
            // 转成数组
            let data = package.to_byte_array();

            // 加密
            let mut final_result = Vec::<u8>::new();
            let mut read_buffer = buffer::RefReadBuffer::new(data);
            let mut buffer = [0; 4096];
            let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

            {
                let mut encryptor = aes::ecb_encryptor(KeySize::KeySize256, pwd, PkcsPadding);
                loop {
                    let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

                    final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

                    match result {
                        BufferResult::BufferUnderflow => break,
                        BufferResult::BufferOverflow => {}
                    }
                }
            }

            let result_byte_arr = final_result.as_slice();
            let data_length = (result_byte_arr.len() as u32).to_le_bytes();
            for x in data_length {
                final_result.insert(0, x);
            }
            final_result.insert(0, 0x2f);
            final_result.insert(0, 0x0f);
            let x1 = final_result.as_slice();

            // eprintln!("write data:{:02x?}", x1);
            match writer.write_all(x1).await {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("err {}", e);
                    break;
                }
            }
        }
        let _ = writer.shutdown().await;
        let _ = close_sender.send(2);
    }
}