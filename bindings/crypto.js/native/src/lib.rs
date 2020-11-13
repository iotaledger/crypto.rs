#[allow(unused)]

use neon::prelude::*;
use neon::{register_module};

// use getrandom;
use crypto::rand;

struct CryptoTask {
    length: f64,
}

impl Task for CryptoTask {
    type Output = String;
    type Error = String;
    type JsEvent = JsString;

    // perform the async task
    fn perform(&self) -> Result<Self::Output, Self::Error> {
        let mut buf = self.length.to_be_bytes();

        // this is where we could switch out the various functions with an enum, for example
        rand::fill(&mut buf).unwrap(); //.map_err(|e| e.to_string())?;

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
    rand::fill(&mut buf).unwrap(); // .map_err(|e| cx.error(e.to_string()));

    Ok(cx.string(format!("{:?}", buf)))
}

register_module!(mut cx, {
    cx.export_function("asyncRandom", async_random);
    cx.export_function("syncRandom", sync_random)
});
