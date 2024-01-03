use std::io::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::symm::{Cipher, decrypt, encrypt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::spawn;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

#[derive(Copy, Clone)]
pub enum TunnelStatus {
    Success,
    WaitLogin,
    Logout,
}

/// 隧道结构体
pub struct Tunnel {
    password_md5: String,
    upload: Arc<RwLock<i64>>,
    download: Arc<RwLock<i64>>,
    status: Arc<RwLock<TunnelStatus>>,
    ping_time: Arc<RwLock<u128>>,
    ping_delay: Arc<RwLock<u128>>,
    sender: Sender<TunnelPackage>,
    tcp_reader: Option<OwnedReadHalf>,
    tcp_writer: OwnedWriteHalf,
    reader_job: Option<JoinHandle<()>>,
    pub host: String,
    pub port: u16,
}

impl Tunnel {
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
        let package = TunnelPackage::new(PackageCmd::Login, PackageProtocol::TCP, None, None, Some(self.password_md5.clone().into()));
        let _ = self.write_to_tunnel(package).await;
    }

    /// 开始Tcp读取线程
    async fn start_reader_job(&mut self) {
        let tcp_reader = self.tcp_reader.take();
        if tcp_reader.is_none() {
            return;
        }
        let mut tcp_reader = tcp_reader.unwrap();

        let sender = self.sender.clone();
        let password_md5 = self.password_md5.clone();
        let login_success = self.status.clone();
        let ping_delay = self.ping_delay.clone();
        let ping_time = self.ping_time.clone();
        let download = self.download.clone();

        let reader_job = spawn(async move {
            let mut buffer_tmp: Vec<u8> = Vec::new();
            let mut data = [0; 8192];

            'read_buff: loop {
                match tcp_reader.read(&mut data).await {
                    Ok(0) => {
                        break;
                    }
                    Ok(n) => {
                        let mut write_guard = download.write().await;
                        *write_guard += n as i64;
                        buffer_tmp.append(&mut data[..n].to_vec());
                        'read_package: loop {
                            match buffer_to_tunnel_package(&mut buffer_tmp, password_md5.as_bytes()) {
                                Ok(tunnel_opt) => {
                                    // 转成结构体
                                    if let Some(tunnel_package) = tunnel_opt {
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
                                                *write_guard = TunnelStatus::Success;
                                            }
                                            PackageCmd::LoginFail => {
                                                eprintln!("tunnel login fail");
                                                let mut write_guard = login_success.write().await;
                                                *write_guard = TunnelStatus::Logout;
                                            }
                                            PackageCmd::ProtocolError => {
                                                eprintln!("tunnel protocol error");
                                                let mut write_guard = login_success.write().await;
                                                *write_guard = TunnelStatus::Logout;
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
                };
            };
            let mut write_guard = login_success.write().await;
            *write_guard = TunnelStatus::Logout;
        });
        self.reader_job = Some(reader_job);
    }
}

impl Tunnel {
    pub async fn new(host: String, port: u16, password: String, sender: Sender<TunnelPackage>) -> Result<Tunnel, Error> {
        match Tunnel::connect(host.to_string(), port).await {
            Ok((r, w)) => {
                // // 加密解密密钥
                let md5_pwd = md5::compute(password.as_bytes());

                let mut tunnel = Tunnel {
                    host,
                    port,
                    password_md5: format!("{:x}", md5_pwd),
                    upload: Arc::new(RwLock::new(0)),
                    download: Arc::new(RwLock::new(0)),
                    status: Arc::new(RwLock::new(TunnelStatus::WaitLogin)),
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

    /// 获取上传流量
    pub async fn get_upload(&self) -> i64 {
        let mut x = self.upload.write().await;
        let u = x.clone();
        *x = 0;
        u
    }

    /// 获取下载流量
    pub async fn get_download(&self) -> i64 {
        let mut x = self.download.write().await;
        let u = x.clone();
        *x = 0;
        u
    }

    /// 获取隧道状态
    pub async fn get_status(&self) -> TunnelStatus {
        return self.status.read().await.clone();
    }

    /// 获取Ping延迟
    pub async fn get_ping_delay(&self) -> u128 {
        *self.ping_delay.read().await
    }

    /// 断开连接
    pub async fn disconnect(&mut self) {
        // 设置状态
        let mut write_guard = self.status.write().await;
        *write_guard = TunnelStatus::Logout;
        // 停止读线程
        if let Some(reader_job) = self.reader_job.take() {
            reader_job.abort();
        }
        eprintln!("tunnel {}:{} disconnect", self.host, self.port);
    }

    /// 写数据包到Tunnel上
    pub async fn write_to_tunnel(&mut self, mut tunnel_package: TunnelPackage) -> Result<(), String> {
        // eprintln!("tunnel write to tunnel:{:?}", tunnel_package);
        let pwd = self.password_md5.as_bytes();
        // 转成数组
        let mut vec1 = Vec::new();
        tunnel_package.to_byte_array(vec1.as_mut());

        // 加密
        let cipher = Cipher::aes_256_ecb();
        let mut final_result = match encrypt(cipher, pwd, None, vec1.as_slice()) {
            Ok(vec) => { vec }
            Err(e) => { return Err(e.to_string()); }
        };

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
                Err(e.to_string())
            }
        }
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

    let mut new_buffer = buffer_tmp.split_off((data_length + 6) as usize);
    let read_data_arr = &buffer_tmp.as_slice()[6..];

    // 解密
    let cipher = Cipher::aes_256_ecb();
    let result = match decrypt(cipher, password_md5_byte, None, read_data_arr) {
        Ok(vec) => { vec }
        Err(e) => { return Err(e.to_string()); }
    };


    // 转成结构体
    let data = result.as_slice();
    let tunnel_package = TunnelPackage::from_byte_array(data);
    buffer_tmp.clear();
    buffer_tmp.append(&mut new_buffer);


    return Ok(Some(tunnel_package));
}
