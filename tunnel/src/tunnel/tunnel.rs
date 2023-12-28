use std::io::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crypto::{aes, buffer};
use crypto::aes::KeySize;
use crypto::blockmodes::PkcsPadding;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::md5::Md5;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

pub enum TunnelLoginStatus {
    Success,
    Fail,
    WaitLogin,
    Logout,
}

/// 隧道结构体
pub struct Tunnel {
    host: String,
    port: u16,
    password: String,
    password_md5: String,
    upload: Arc<RwLock<i64>>,
    download: Arc<RwLock<i64>>,
    login_status: Arc<RwLock<TunnelLoginStatus>>,
    ping_time: Arc<RwLock<u128>>,
    ping_delay: Arc<RwLock<u128>>,
    sender: Sender<TunnelPackage>,
    tcp_reader: Option<OwnedReadHalf>,
    tcp_writer: OwnedWriteHalf,
    reader_job: Option<JoinHandle<()>>,
}

impl Tunnel {
    pub async fn new(host: String, port: u16, password: String, sender: Sender<TunnelPackage>) -> Result<Tunnel, Error> {
        match Tunnel::connect(host.to_string(), port).await {
            Ok((r, w)) => {
                // // 加密解密密钥
                let mut hasher = Md5::new();
                hasher.input_str(password.as_str());
                let md5_pwd = hasher.result_str();

                let mut tunnel = Tunnel {
                    host,
                    port,
                    password,
                    password_md5: md5_pwd,
                    upload: Arc::new(RwLock::new(0)),
                    download: Arc::new(RwLock::new(0)),
                    login_status: Arc::new(RwLock::new(TunnelLoginStatus::WaitLogin)),
                    ping_time: Arc::new(RwLock::new(0)),
                    ping_delay: Arc::new(RwLock::new(0)),
                    sender,
                    tcp_reader: Some(r),
                    tcp_writer: w,
                    reader_job: None,
                };
                // 开启读线程
                tunnel.start_reader_job().await;
                // 登录
                tunnel.login_tunnel().await;
                // 发送ping命令
                tunnel.send_ping().await;
                Ok(tunnel)
            }
            Err(e) => { Err(e) }
        }
    }
    /// 连接隧道
    async fn connect(host: String, port: u16) -> Result<(OwnedReadHalf, OwnedWriteHalf), Error> {
        match TcpStream::connect((host, port)).await {
            Ok(tcp_stream) => {
                eprintln!("tunnel connect success");
                Ok(tcp_stream.into_split())
            }
            Err(e) => { Err(e) }
        }
    }


    /// 断开连接
    pub async fn disconnect(&mut self) {
        // 设置状态
        let mut write_guard = self.login_status.write().await;
        *write_guard = TunnelLoginStatus::Logout;
        // 停止读线程
        if let Some(reader_job) = self.reader_job.take() {
            reader_job.abort()
        }
    }

    /// 写数据包到Tunnel上
    pub async fn write_to_tunnel(&mut self, mut tunnel_package: TunnelPackage) -> Result<(), Error> {
        // eprintln!("tunnel write to tunnel:{:?}", tunnel_package);
        let pwd = self.password_md5.as_bytes();
        // 转成数组
        let data = tunnel_package.to_byte_array();

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
        match self.tcp_writer.write_all(x1).await {
            Ok(_) => {
                let _ = self.tcp_writer.flush().await;
                let mut write_guard = self.upload.write().await;
                *write_guard += x1.len() as i64;
                Ok(())
            }
            Err(e) => {
                eprintln!("tunnel write err {}", e);
                Err(e)
            }
        }
    }

    async fn send_ping(&mut self) {
        *self.ping_time.write().await = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let package = TunnelPackage::new(PackageCmd::PING, PackageProtocol::TCP, None, None, None);
        let _ = self.write_to_tunnel(package).await;
    }

    /// 登录tunnel
    async fn login_tunnel(&mut self) {
        let package = TunnelPackage::new(PackageCmd::Login, PackageProtocol::TCP, None, None, Some(self.password_md5.clone().into_bytes()));
        let _ = self.write_to_tunnel(package).await;
    }

    /// 开始Tcp读取线程
    async fn start_reader_job(&mut self) {
        let mut tcp_reader = self.tcp_reader.take();
        if tcp_reader.is_none() {
            return;
        }
        let mut tcp_reader = tcp_reader.unwrap();

        let sender = self.sender.clone();
        let password_md5 = self.password_md5.clone();
        let login_success = self.login_status.clone();
        let ping_delay = self.ping_delay.clone();
        let ping_time = self.ping_time.clone();

        let reader_job = spawn(async move {
            let mut buffer_tmp: Vec<u8> = Vec::new();
            let mut data = [0; 8192];

            'read_buff: loop {
                match tcp_reader.read(&mut data).await {
                    Ok(0) => {
                        break;
                    }
                    Ok(n) => {
                        buffer_tmp.append(&mut data[..n].to_vec());
                        'read_package: loop {
                            match buffer_to_tunnel_package(&mut buffer_tmp, password_md5.as_bytes()) {
                                Ok(tunnel_opt) => {
                                    // 转成结构体
                                    if let Some(mut tunnel_package) = tunnel_opt {
                                        // eprintln!("tunnel read package: {:?}", tunnel_package);
                                        match tunnel_package.cmd {
                                            PackageCmd::Login => {}
                                            PackageCmd::NewConnect => {}
                                            PackageCmd::CloseConnect => {
                                                if let Err(_) = sender.send(tunnel_package).await {
                                                    break 'read_buff;
                                                }
                                            }
                                            PackageCmd::TData => {
                                                // if let Some(d) = tunnel_package.data.take() {
                                                //     eprintln!("{}", String::from_utf8_lossy(d.clone().as_slice()));
                                                //     tunnel_package.data = Some(d);
                                                // }
                                                if let Err(_) = sender.send(tunnel_package).await {
                                                    break 'read_buff;
                                                }
                                            }
                                            PackageCmd::PING => {}
                                            PackageCmd::LoginSuccess => {
                                                eprintln!("tunnel login success");
                                                let mut write_guard = login_success.write().await;
                                                *write_guard = TunnelLoginStatus::Success;
                                            }
                                            PackageCmd::LoginFail => {
                                                eprintln!("tunnel login fail");
                                                let mut write_guard = login_success.write().await;
                                                *write_guard = TunnelLoginStatus::Fail;
                                            }
                                            PackageCmd::ProtocolError => {
                                                eprintln!("tunnel protocol error");
                                                let mut write_guard = login_success.write().await;
                                                *write_guard = TunnelLoginStatus::Fail;
                                            }
                                            PackageCmd::PONG => {
                                                let ping_time = *ping_time.read().await;
                                                let delay = SystemTime::now()
                                                    .duration_since(UNIX_EPOCH)
                                                    .unwrap()
                                                    .as_millis() - ping_time;
                                                eprintln!("tunnel delay {}ms", delay);
                                                *ping_delay.write().await = delay;
                                            }
                                            PackageCmd::NONE => {}
                                        }
                                    } else {
                                        break 'read_package;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("{}", e);
                                    break 'read_package;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("tunnel read err {}", e);
                        break;
                    }
                }
            }
        });
        self.reader_job = Some(reader_job);
    }
}

/// 数据包转TunnelPackage结构体
fn buffer_to_tunnel_package(buffer_tmp: &mut Vec<u8>, password_md5_byte: &[u8]) -> Result<Option<TunnelPackage>, String> {
    // 数据长度小于6
    if buffer_tmp.len() < 6 {
        return Ok(None);
    }

    // 校验数据头
    if buffer_tmp[0] != 0x0f && buffer_tmp[1] != 0x2f {
        return Err("数据包头错误".to_string());
    }

    let data_length = i32::from_be_bytes([buffer_tmp[2], buffer_tmp[3], buffer_tmp[4], buffer_tmp[5]]);
    if buffer_tmp.len() < (data_length + 6) as usize {
        return Ok(None);
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
        let mut decryptor = aes::ecb_decryptor(KeySize::KeySize256, password_md5_byte, PkcsPadding);
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
    buffer_tmp.clear();
    buffer_tmp.append(&mut new_buffer);
    return Ok(Some(tunnel_package));
}