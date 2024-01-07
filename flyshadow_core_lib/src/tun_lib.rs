use std::ffi::CString;
use std::mem::forget;
use std::os::raw::c_char;
use std::sync::Arc;

use tokio::runtime::Runtime;
use tokio::spawn;
use tokio::sync::mpsc::channel;

use tunnel::context::context::TunnelContext;
use tunnel::tun::packet::{Packet, Protocol, Version};
use tunnel::tun::tcp_pipe_context::TcpPipeContext;
use tunnel::tun::tun::Tun;
use tunnel::tunnel::tunnel_package::{PackageCmd, PackageProtocol, TunnelPackage};

/// 新建Tun对象
#[no_mangle]
pub extern "C" fn new_tun(rt: i64, context_ptr: i64, port: i32) -> i64 {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    let tun = Tun::new(context_clone, port as usize);

    forget(tc);
    forget(rt);
    Box::into_raw(Box::new(tun)) as i64
}


/// 启动Tun
#[no_mangle]
pub extern "C" fn start_tun(rt: i64, t: i64) -> *mut c_char {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let mut t = unsafe { Box::from_raw(t as *mut Tun) };

    let result = rt.block_on(async move {
        match t.start().await {
            Ok(_) => {
                "".to_string()
            }
            Err(e) => {
                e.to_string()
            }
        }
    });
    forget(rt);
    return CString::new(result).unwrap().into_raw();
}

#[no_mangle]
pub extern "C" fn send_to_tun(rt: i64, context_ptr: i64, input: *const u8, input_size: usize) {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context = Arc::clone(tc.as_ref());

    let input_slice: &[u8] = unsafe { std::slice::from_raw_parts(input, input_size) };
    let data = input_slice.to_vec();

    let (sender, mut receiver) = channel::<Vec<u8>>(10);
    let sender1 = sender.clone();
    let tcp_pipe_context = Arc::new(TcpPipeContext::new());
    let tcp_pipe_context1 = tcp_pipe_context.clone();

    rt.block_on(async move {
        let data_len = data.len();

        let mut packet = Packet::from_byte(data);
        let packet_len = packet.get_total_len();
        if packet_len == -1 || data_len < packet_len as usize {
            return;
        }

        if packet.get_version() == Version::IPV4 {
            eprintln!("read client data: ");
            match packet.get_protocol() {
                Protocol::ICMP => {}
                Protocol::TCP => {
                    // 握手
                    if packet.is_syn() {
                        eprintln!("packet syn ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                        if let Some(tcp_pipe) = tcp_pipe_context1.create_pipe(&packet).await {
                            let sender_clone = sender.clone();
                            let tcp_pipe_context_clone = tcp_pipe_context.clone();
                            let (sender, mut receiver) = channel::<TunnelPackage>(10);

                            // 处理隧道返回的数据
                            spawn(async move {
                                while let Some(d) = receiver.recv().await {
                                    match d.cmd {
                                        PackageCmd::Login => {}
                                        PackageCmd::NewConnect => {}
                                        PackageCmd::CloseConnect => {
                                            eprintln!("tunnel send close connect ");
                                            if let Some(source_addr) = d.source_address {
                                                if let Some(target_addr) = d.target_address {
                                                    if let Some(pipe) = tcp_pipe_context_clone.get_pipe_by_key(&format!("{}-{}", source_addr, target_addr)).await {
                                                        let vec = pipe.write().await.do_fin();
                                                        let _ = sender_clone.send(vec).await;
                                                    } else {
                                                        eprintln!("get none pipe:{}", &format!("{}-{}", source_addr, target_addr))
                                                    }
                                                    tcp_pipe_context_clone.remove_pipe_by_key(&format!("{}-{}", source_addr, target_addr)).await;
                                                }
                                            }
                                        }
                                        PackageCmd::TData => {
                                            if let Some(data) = d.data {
                                                eprintln!("read tunnel data:{}", data.len());
                                                if let Some(source_addr) = d.source_address {
                                                    if let Some(target_addr) = d.target_address {
                                                        if let Some(pipe) = tcp_pipe_context_clone.get_pipe_by_key(&format!("{}-{}", source_addr, target_addr)).await {
                                                            let vec = pipe.write().await.do_psh(data);
                                                            let _ = sender_clone.send(vec).await;
                                                        } else {
                                                            eprintln!("get none pipe:{}", &format!("{}-{}", source_addr, target_addr))
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        PackageCmd::PING => {}
                                        PackageCmd::LoginSuccess => {}
                                        PackageCmd::LoginFail => {}
                                        PackageCmd::ProtocolError => {}
                                        PackageCmd::PONG => {}
                                        PackageCmd::NONE => {}
                                    }
                                }
                            });
                            context.add_proxy_mapping(format!("{}:{}", packet.get_source_addr(), packet.get_source_port()), sender).await;
                            let _ = context.tunnel_connect_server(format!("{}:{}", packet.get_target_addr(), packet.get_target_port()),
                                                                  format!("{}:{}", packet.get_source_addr(), packet.get_source_port())).await;
                            let vec = tcp_pipe.read().await.do_ack_syn(&mut packet);
                            eprintln!("do ack syn , send to client:  ");
                            // print(vec.as_slice());
                            let _ = sender1.send(vec).await;
                        }
                    }
                    if packet.is_ack() {
                        eprintln!("packet ack ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                    }
                    // 处理客户端推送过来的的数据
                    if packet.is_psh() {
                        eprintln!("packet psh ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                        if let Some(tcp_pipe) = tcp_pipe_context1.get_pipe(&packet).await {
                            // 发送数据到隧道
                            eprintln!("send data to tunnel size:{}", packet.get_data().len());
                            if packet.get_data().len() > 0 {
                                let _ = context.tunnel_send_data(format!("{}:{}", packet.get_target_addr(), packet.get_target_port()),
                                                                 format!("{}:{}", packet.get_source_addr(), packet.get_source_port()),
                                                                 packet.get_data().to_vec(), PackageProtocol::TCP).await;
                            }
                            let vec = tcp_pipe.write().await.do_ack_psh(&mut packet);
                            eprintln!("do ack psh ,send to client: ");
                            // print(vec.as_slice());
                            let _ = sender1.send(vec).await;
                        } else {
                            eprintln!("not pipe");
                        }
                    }
                    // 处理客户端Fin数据包
                    if packet.is_fin() {
                        eprintln!("packet fin ,source:{}:{}  target:{}:{}", packet.get_source_addr(), packet.get_source_port(), packet.get_target_addr(), packet.get_target_port());
                        if let Some(tcp_pipe) = tcp_pipe_context1.get_pipe(&packet).await {
                            tcp_pipe_context1.remove_pipe(&packet).await;
                            // 发送数据到隧道
                            if packet.get_data().len() > 0 {
                                let _ = context.tunnel_close_server(format!("{}:{}", packet.get_source_addr(), packet.get_source_port())).await;
                            }
                            let vec = tcp_pipe.write().await.do_ack_fin(&mut packet);
                            eprintln!("do ack fin ,send to client: ");
                            // print(vec.as_slice());
                            let _ = sender1.send(vec).await;
                        } else {
                            eprintln!("not pipe");
                        }
                    }
                }
                Protocol::UDP => {}
                Protocol::Unknown => {}
            }
        }

        while let Some(data) = receiver.recv().await {
            eprintln!("tun receiver data: {:?}", data);
        }
    });

    forget(rt);
}