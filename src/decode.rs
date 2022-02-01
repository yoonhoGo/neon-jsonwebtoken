use crate::jsonwebtoken_mod::header::ToObject;
use crate::neon_serde;
use jsonwebtoken::dangerous_insecure_decode;
use neon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub fn decode(mut cx: FunctionContext) -> JsResult<JsValue> {
  let jwt = cx.argument::<JsString>(0)?.value(&mut cx);
  let options = cx.argument_opt(1);
  let decode_options: DecodeOptions =
    neon_serde::from_value_opt(&mut cx, options).unwrap_or(DecodeOptions::default());

  let payload = dangerous_insecure_decode::<Claims>(&jwt).unwrap();

  let claim_object = neon_serde::to_value(&mut cx, &payload.claims).unwrap();

  if !decode_options.complete.unwrap_or(false) {
    return Ok(claim_object);
  }

  let decode_result = cx.empty_object();
  decode_result.set(&mut cx, "payload", claim_object)?;

  let header = payload.header.to_object(&mut cx);

  decode_result.set(&mut cx, "header", header)?;
  let signature = cx.string(jwt.split(".").nth(2).unwrap().to_string());
  decode_result.set(&mut cx, "signature", signature)?;

  Ok(
    decode_result
      .downcast_or_throw::<JsValue, _>(&mut cx)
      .unwrap(),
  )
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DecodeOptions {
  complete: Option<bool>,
}

impl Default for DecodeOptions {
  fn default() -> Self {
    DecodeOptions {
      complete: Some(false),
    }
  }
}
