// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[macro_use]
extern crate serde_derive;
use crypto;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[derive(Debug)]
#[repr(C)]
pub struct Cmd {
    feature: *const c_char,
    function: *const c_char,
    size: f64,
    payload: *const c_char,
    returns: *const c_char,
}

fn to_str<'a>(pointer: *const c_char) -> &'a str {
    let c_str = unsafe {
        assert!(!pointer.is_null());
        CStr::from_ptr(pointer)
    };
    c_str.to_str().unwrap()
}

#[no_mangle]
pub unsafe extern "C" fn sync(cmd: Cmd) -> *const c_char {
    match to_str(cmd.feature) {
        "rand" => {
            let mut buf = cmd.size.to_le_bytes();
            let _t = crypto::rand::fill(&mut buf).map_err(|e| e.to_string());
            let s = CString::new(format!("{:?}", buf)).unwrap();
            let p = s.as_ptr();
            std::mem::forget(s);
            p
        }
        "ed25519" => match to_str(cmd.function) {
            "generate" => {
                let kk = crypto::ed25519::SecretKey::generate().unwrap();
                let s = CString::new(format!("{:?}", kk)).unwrap();
                s.as_ptr()
            }
            _ => {
                let s = CString::new(format!("4es")).unwrap();
                s.as_ptr()
            }
        },
        _ => {
            let s = CString::new(format!("4")).unwrap();
            s.as_ptr()
        }
    }
}
