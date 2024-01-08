use std::ffi::CString;
use std::mem::forget;
use std::os::raw::c_char;
use std::sync::Arc;

use tokio::runtime::Runtime;

use tunnel::context::context::TunnelContext;
use tunnel::proxy::proxy::Proxy;

/// 新建代理对象
#[no_mangle]
pub extern "C" fn new_proxy(context_ptr: i64, port: i32) -> i64 {
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    let proxy = Proxy::new(context_clone, port as usize);

    forget(tc);
    Box::into_raw(Box::new(proxy)) as i64
}

/// 启动代理
#[no_mangle]
pub extern "C" fn start_proxy(rt: i64, p: i64) -> *mut c_char {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let mut p = unsafe { Box::from_raw(p as *mut Proxy) };

    let result = rt.block_on(async move {
        let result = match p.start().await {
            Ok(_) => { "".to_string() }
            Err(e) => {
                e.to_string()
            }
        };
        forget(p);
        result
    });
    forget(rt);
    return CString::new(result).unwrap().into_raw();
}