use std::cell::RefCell;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;

use tokio::spawn;
use tokio::time::sleep;

use tunnel::context::context::TunnelContext;
use tunnel::tunnel::tunnel::Tunnel;

#[tokio::main]
async fn main() {
    let mut tunnel = Tunnel::new("47.242.6.116".to_string(), 6001, "855ddy1sg2nczhxh4vgl".to_string());

    let mut receiver = tunnel.close_receiver();
    let mut tunnel_package_receiver = tunnel.tunnel_package_receiver().unwrap();

    spawn(async move {
        while let Some(tunnelPackage) = tunnel_package_receiver.recv().await {
            println!("tunnel package: {:?}", tunnelPackage);
        }
    });

    spawn(async move {
        let _ = tunnel.connect().await;
        println!("tunnel connect finish")
    });


    spawn(async move {
        let r = receiver.recv().await;
        println!("close, {:?}", r);
    });


    // run_tunnel().await;

    let tunnel_context = Arc::new(RefCell::new(Box::new(TunnelContext::new())));

    let binding = tunnel_context.clone();
    let mut arc = binding.as_ref().borrow_mut();

    arc.tunnel = Some(tunnel);

    // let mut proxy = Proxy::new(tunnel_context.clone(), 6445);
    // match proxy.start().await {
    //     Ok(_) => {
    //         eprintln!("start proxy")
    //     }
    //     Err(e) => { eprintln!("start proxy err : {}", e) }
    // }


    // sleep(Duration::from_secs(20)).await;

    // proxy.stop_listener();

    sleep(Duration::from_secs(2000)).await;
}

async fn run_tunnel() {
    let mut tunnel = Tunnel::new("47.242.6.116".to_string(), 6001, "855ddy1sg2nczhxh4vgl".to_string());

    let mut receiver = tunnel.close_receiver();
    let mut tunnel_package_receiver = tunnel.tunnel_package_receiver().unwrap();

    spawn(async move {
        while let Some(tunnelPackage) = tunnel_package_receiver.recv().await {
            println!("tunnel package: {:?}", tunnelPackage);
        }
    });

    spawn(async move {
        let _ = tunnel.connect().await;
        println!("tunnel connect finish")
    });


    spawn(async move {
        let r = receiver.recv().await;
        println!("close, {:?}", r);
    });

    sleep(Duration::from_secs(2000)).await;
}