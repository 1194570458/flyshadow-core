use std::mem::forget;
use std::sync::Arc;

use tokio::runtime::Runtime;

use tunnel::context::context::TunnelContext;
use tunnel::tun::tun::Tun;

/// 新建Tun对象
#[no_mangle]
pub extern "C" fn new_tun(rt: i64,context_ptr: i64) -> i64 {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let tc = unsafe { Box::from_raw(context_ptr as *mut Arc<TunnelContext>) };
    let context_clone = Arc::clone(tc.as_ref());

    let tun = rt.block_on(async {
        Tun::new(context_clone)
    });

    forget(tc);
    forget(rt);
    Box::into_raw(Box::new(tun)) as i64
}


#[no_mangle]
pub extern "C" fn send_to_tun(rt: i64, t: i64, input: *const u8, input_size: usize) {
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let t = unsafe { Box::from_raw(t as *mut Tun) };

    let input_slice: &[u8] = unsafe { std::slice::from_raw_parts(input, input_size) };
    let data = input_slice.to_vec();

    rt.block_on(async move {
        eprintln!("tun receiver data: {:02x?}", data);
        t.handler_tun_data(data).await;

        forget(t);
    });

    forget(rt);
}

#[no_mangle]
pub extern "C" fn get_tun_data(rt: i64, t: i64, out_put_size: *mut usize) ->*mut u8{
    let rt = unsafe { Box::from_raw(rt as *mut Runtime) };
    let t = unsafe { Box::from_raw(t as *mut Tun) };

    let (result,t) = rt.block_on(async move {
        let result = t.get_tun_data().await;
        (result,t)
    });

    forget(t);
    forget(rt);

    let result_len = result.len();
    let mut boxed_data = result.into_boxed_slice();

    unsafe {
        *out_put_size = result_len;
        let x = boxed_data.as_mut_ptr();
        forget(boxed_data);
        x
    }
}