use std::str::SplitAsciiWhitespace;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use tokio::spawn;
use tokio::time::sleep;

use tunnel::context::context::TunnelContext;
use tunnel::proxy::proxy::Proxy;

#[tokio::main]
async fn main() {


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

    let tunnel_context1 = tunnel_context.clone();
    spawn(async move{
        loop {
            sleep(Duration::from_secs(1)).await;
            println!("upload: {}", tunnel_context1.get_tunnel_upload().await);
            println!("download: {}", tunnel_context1.get_tunnel_download().await);
        }
    });

    let tunnel_context2 = tunnel_context.clone();
    spawn(async move{
        sleep(Duration::from_secs(10)).await;
        tunnel_context2.close_tunnel().await;
        sleep(Duration::from_secs(5)).await;
        match tunnel_context.connect_tunnel("47.242.6.116".to_string(), 6001, "855ddy1sg2nczhxh4vgl".to_string()).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}", e);
            }
        };
    });

    sleep(Duration::from_secs(20000)).await;
}
