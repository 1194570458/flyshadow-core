use std::ffi::CStr;
use std::mem::forget;
use std::os::raw::c_char;
use std::sync::Arc;

use tokio::runtime::{Builder, Runtime};

use tunnel::context::context::TunnelContext;

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