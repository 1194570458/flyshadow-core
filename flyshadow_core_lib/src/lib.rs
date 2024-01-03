use std::ffi::{CStr, CString};
use std::mem::forget;
use std::os::raw::c_char;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};
use tunnel::context::context::TunnelContext;
use tunnel::proxy::proxy::Proxy;

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn new_runtime() -> i64 {
    let runtime = Builder::new_multi_thread().enable_all()
        .build().unwrap();
    Box::into_raw(Box::new(runtime)) as i64
}

#[no_mangle]
pub extern "C" fn new_tunnel_context(rt: i64) -> i64 {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let result = rt.block_on(async {
        let tunnel_context = Arc::new(TunnelContext::new());
        let raw = Box::into_raw(Box::new(tunnel_context));
        raw as i64
    });
    forget(rt);
    result
}

#[no_mangle]
pub extern "C" fn set_domain_rule(rt: i64, context_ptr: i64, rule: *const c_char) {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    rt.block_on(async {
        let rule = unsafe { CStr::from_ptr(rule).to_string_lossy() };
        context_clone.set_domain_rule(rule.to_string()).await;
    });
    forget(tc);
    forget(rt);
}

#[no_mangle]
pub extern "C" fn start_proxy(rt: i64, context_ptr: i64, port: u32) -> *mut c_char {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());
    //
    let result = rt.block_on(async move {
        let mut proxy = Proxy::new(context_clone, port as usize);
        let result = match proxy.start().await {
            Ok(_) => { "".to_string() }
            Err(e) => {
                e.to_string()
            }
        };
        result
    });
    forget(tc);
    forget(rt);
    return CString::new(result).unwrap().into_raw();
}

#[no_mangle]
pub extern "C" fn connect_tunnel(rt: i64, context_ptr: i64, host: *const c_char, port: u32, password: *const c_char) -> *mut c_char {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());
    let result = rt.block_on(async move {
        let host = unsafe { CStr::from_ptr(host).to_string_lossy() };
        let password = unsafe { CStr::from_ptr(password).to_string_lossy() };
        match context_clone.connect_tunnel(host.to_string(), port as u16, password.to_string()).await {
            Ok(_) => { "".to_string() }
            Err(e) => {
                e.to_string()
            }
        }
    });
    forget(tc);
    forget(rt);
    return CString::new(result).unwrap().into_raw();
}

#[no_mangle]
pub extern "C" fn close_tunnel(rt: i64, context_ptr: i64) {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    rt.block_on(async move {
        context_clone.close_tunnel().await;
    });

    forget(tc);
    forget(rt);
}

#[no_mangle]
pub extern "C" fn get_tunnel_upload(rt: i64, context_ptr: i64) -> i64 {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    let result = rt.block_on(async move {
        context_clone.get_tunnel_upload().await
    });

    forget(tc);
    forget(rt);
    result
}

#[no_mangle]
pub extern "C" fn get_tunnel_download(rt: i64, context_ptr: i64) -> i64 {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    let result = rt.block_on(async move {
        context_clone.get_tunnel_download().await
    });

    forget(tc);
    forget(rt);
    result
}

#[no_mangle]
pub extern "C" fn get_tunnel_ping_delay(rt: i64, context_ptr: i64) -> i32 {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    let result = rt.block_on(async move {
        context_clone.get_tunnel_ping_delay().await
    });

    forget(tc);
    forget(rt);
    result
}
#[no_mangle]
pub extern "C" fn get_tunnel_status(rt: i64, context_ptr: i64) -> i32 {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    let result = rt.block_on(async move {
        context_clone.get_tunnel_status().await
    });

    forget(tc);
    forget(rt);
    result
}