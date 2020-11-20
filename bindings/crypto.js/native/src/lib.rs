#[allow(dead_code)]
#[allow(non_snake_case)]
use neon::prelude::*;
use neon::register_module;
#[macro_use]
extern crate neon;
#[macro_use]
extern crate neon_serde;
#[macro_use]
extern crate serde_derive;

use crypto;

fn sync_random(mut cx: FunctionContext) -> JsResult<JsArray> {
    let mut buf = cx.argument::<JsNumber>(0)?.value().to_le_bytes();
    // complains about result possibly being an error, which should be handled - but
    // we want that to throw in JS land.
    crypto::rand::fill(&mut buf).unwrap(); // .map_err(|e| cx.error(e.to_string()));

    let js_array = JsArray::new(&mut cx, buf.len() as u32);

    buf.iter().enumerate().for_each(|e| {
        let (i, obj) = e;
        let _number = JsNumber::new(&mut cx, *obj as f64);
        let _ = js_array.set(&mut cx, i as u32, _number);
    });
    Ok(js_array)
}

fn sync_ed25519_generate(mut cx: FunctionContext) -> JsResult<JsValue> {
    let ed = crypto::ed25519::SecretKey::generate().unwrap();
    let js_value = neon_serde::to_value(&mut cx, &ed)?;
    Ok(js_value)
}

register_module!(mut m, {
    m.export_function("random", sync_random)?;
    m.export_function("ed25519Generate", sync_ed25519_generate)?;
    Ok(())
});

