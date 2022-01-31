use jsonwebtoken::{encode, EncodingKey, Header};
use neon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    // sub: String,
    // exp: usize,
    // aud: String,
    #[serde(default = "default_iat")]
    iat: usize,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

fn default_iat() -> usize {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH).unwrap();

    since_the_epoch.as_secs() as usize
}

fn to_json<'a>(cx: &mut FunctionContext<'a>, obj: Handle<JsObject>) -> JsResult<'a, JsString> {
    let null = cx.null();
    let json = cx
        .global()
        .get(cx, "JSON")?
        .downcast_or_throw::<JsObject, _>(cx)?;
    let stringify = json
        .get(cx, "stringify")?
        .downcast_or_throw::<JsFunction, _>(cx)?;

    let json_string = stringify
        .call(cx, null, vec![obj])?
        .downcast_or_throw::<JsString, _>(cx)?;

    Ok(json_string)
}

fn sign(mut cx: FunctionContext) -> JsResult<JsString> {
    let payload: Handle<JsObject> = cx.argument(0)?;
    let key = cx.argument::<JsString>(1)?.value(&mut cx);

    let json_string = to_json(&mut cx, payload)?.value(&mut cx);
    let json: Claims = serde_json::from_str(json_string.as_str()).unwrap();
    let token = encode(
        &Header::default(),
        &json,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .unwrap();

    Ok(cx.string(token))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("sign", sign)?;
    Ok(())
}
