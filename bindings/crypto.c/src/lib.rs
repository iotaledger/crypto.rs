// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[allow(dead_code)]
#[macro_use]
extern crate serde_derive;
use libc::c_char;
use crypto;
use std::ffi::CString;


#[derive(Serialize, Deserialize, Debug)]
#[repr(C)]
pub struct Cmd {
    feature: String,
    function: String,
    size: f64,
    payload: String,
    returns: String,
}

#[no_mangle]
pub unsafe extern "C" fn sync(cmd: Cmd) -> *const c_char {
    match &cmd.feature as &str {
        "rand" => {
            let mut buf = cmd.size.to_le_bytes();
            let _t = crypto::rand::fill(&mut buf).map_err(|e| e.to_string());
            let s = CString::new(format!("{:?}", buf)).unwrap();
            let p = s.as_ptr();
            std::mem::forget(s);
            p
        },
        "ed25519" => {
            match &cmd.function as &str {
                "generate" => {
                    let kk = crypto::ed25519::SecretKey::generate().unwrap();
                    let s = CString::new(format!("{:?}", kk)).unwrap();
                    s.as_ptr()
                },
                _ => {
                    let s = CString::new(format!("4es")).unwrap();
                    s.as_ptr()
                },         
            }       
        },
        _ => {
            let s = CString::new(format!("4")).unwrap();
            s.as_ptr()
        },
    }
}
