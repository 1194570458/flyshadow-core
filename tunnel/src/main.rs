use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::channel;
use tokio::time::sleep;

use tunnel::context::context::TunnelContext;
use tunnel::proxy::proxy::Proxy;
use tunnel::tunnel::tunnel::Tunnel;
use tunnel::tunnel::tunnel_package::TunnelPackage;

#[tokio::main]
async fn main() {
    // run_tunnel().await;


    let tunnel_context = Arc::new(TunnelContext::new());

    let mut proxy = Proxy::new(tunnel_context.clone(), 6555);
    match proxy.start().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    };

    match tunnel_context.connect_tunnel("47.242.6.116".to_string(), 6001, "855ddy1sg2nczhxh4vgl".to_string()).await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
        }
    };

    sleep(Duration::from_secs(20000)).await;
}

async fn run_tunnel() {
    let (r, w) = channel::<TunnelPackage>(8192);
    let mut tunnel = Tunnel::new("47.242.6.116".to_string(), 6001, "855ddy1sg2nczhxh4vgl".to_string(), r).await;


    sleep(Duration::from_secs(2000)).await;
}