#[macro_use]
extern crate neon_serde;

#[macro_use]
extern crate serde_derive;

#[allow(dead_code)]

use neon::prelude::*;
use neon::{register_module};
use crypto;

struct CryptoTask {
    length: f64,
}


enum CryptoFn {
    Rand,
    Ed25519,
}

#[derive(Serialize, Deserialize, Debug)]
struct Call {
    feature: String,
    function: String,
    size: f64,
    payload: String,
    returns: String,
}


fn sync(mut cx: FunctionContext) -> JsResult<JsValue> {
    let arg0 = cx.argument::<JsValue>(0)?;
    let call :Call = neon_serde::from_value(&mut cx, arg0)?;
    println!("{:?}", call);
    println!("{:?}", call.feature);

    match &call.feature as &str  {
        "rand" => {
            println!("The function is rand!");
            let mut buf = call.size.to_le_bytes();
            crypto::rand::fill(&mut buf).unwrap(); // .map_err(|e| cx.error(e.to_string()));
            println!("RANDBUF: {:?}", buf);

            Ok(cx.string(format!("{:?}", buf)))
            // let js_value = neon_serde::to_value(&mut cx, &buf)?;
            // Ok(js_value);
            //  Ok(cx.undefined().upcast())
        },
        "ed25519" => {
            println!("The function is ed25519!");
            let sk = crypto::ed25519::SecretKey::generate().map_err(|e| cx.error(e.to_string()));
            // let pk = crypto::ed25519::SecretKey::public_key(&sk)?;
            // println!("{:?}", sk);
            // println!("{:?}", pk);

            // Ok(cx.undefined().upcast())
        },
        _ => {},
    }
    Ok(cx.undefined().upcast())

}


impl Task for CryptoTask {
    type Output = String;
    type Error = String;
    type JsEvent = JsString;

    // perform the async task
    fn perform(&self) -> Result<Self::Output, Self::Error> {
        let mut buf = self.length.to_be_bytes();

        // this is where we could switch out the various functions with an enum, for example
        crypto::rand::fill(&mut buf).unwrap(); //.map_err(|e| e.to_string())?;

        Ok(format!("{:?}", &buf))
    }

    fn complete(
        self,
        mut cx: TaskContext,
        result: Result<Self::Output, Self::Error>,
    ) -> JsResult<Self::JsEvent> {
        Ok(cx.string(result.unwrap()))
    }
}

fn async_random(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let len = cx.argument::<JsNumber>(0)?.value();
    let callback = cx.argument::<JsFunction>(1)?;
    let task = CryptoTask {
        length: len,
    };
    task.schedule(callback);
    Ok(cx.undefined())
}

fn sync_random(mut cx: FunctionContext) -> JsResult<JsString> {
    // complains about result possibly being an error, which should be handled - but
    // we want that to throw in JS land.
    let mut buf = cx.argument::<JsNumber>(0)?.value().to_le_bytes();
    crypto::rand::fill(&mut buf).unwrap(); // .map_err(|e| cx.error(e.to_string()));

    Ok(cx.string(format!("{:?}", buf)))
}


register_module!(mut cx, {
    cx.export_function("asyncRandom", async_random);
    cx.export_function("syncRandom", sync_random);
    cx.export_function("sync", sync)
});
