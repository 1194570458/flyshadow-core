use std::ffi::CString;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        let _ = CString::from_raw(ptr);
    }
}