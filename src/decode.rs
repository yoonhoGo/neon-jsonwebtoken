use crate::neon_serde::from_value;
use crate::neon_serde::to_value;
use jsonwebtoken::dangerous_insecure_decode;
use jsonwebtoken::Algorithm;
use neon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub fn decode(mut cx: FunctionContext) -> JsResult<JsValue> {
  let jwt = cx.argument::<JsString>(0)?.value(&mut cx);
  let options = cx.argument_opt(1);
  let decode_options: DecodeOptions = match options {
    Some(options) => from_value(&mut cx, options).unwrap(),
    _ => DecodeOptions::default(),
  };

  let payload = dangerous_insecure_decode::<Claims>(&jwt).unwrap();

  let claim_object = to_value(&mut cx, &payload.claims).unwrap();

  if !decode_options.complete.unwrap_or(false) {
    return Ok(claim_object);
  }

  let decode_result = cx.empty_object();
  decode_result.set(&mut cx, "payload", claim_object)?;

  let header = cx.empty_object();
  let alg = cx.string(alg_to_string(payload.header.alg));
  header.set(&mut cx, "alg", alg)?;
  insert_header(&mut cx, header, "cty", payload.header.cty);
  insert_header(&mut cx, header, "jku", payload.header.jku);
  insert_header(&mut cx, header, "kid", payload.header.kid);
  insert_header(&mut cx, header, "typ", payload.header.typ);
  insert_header(&mut cx, header, "x5t", payload.header.x5t);
  insert_header(&mut cx, header, "x5u", payload.header.x5u);

  decode_result.set(&mut cx, "header", header)?;
  let signature = cx.string(jwt.split(".").nth(2).unwrap().to_string());
  decode_result.set(&mut cx, "signature", signature)?;

  Ok(
    decode_result
      .downcast_or_throw::<JsValue, _>(&mut cx)
      .unwrap(),
  )
}

fn insert_header(
  cx: &mut FunctionContext,
  header: Handle<JsObject>,
  option_key: &str,
  option: Option<String>,
) {
  if option.is_some() {
    let option_value = cx.string(option.unwrap());
    header.set(cx, option_key, option_value).unwrap();
  }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

fn alg_to_string<'a>(alg: Algorithm) -> &'a str {
  match alg {
    Algorithm::HS256 => "HS256",
    Algorithm::HS384 => "HS384",
    Algorithm::HS512 => "HS512",
    Algorithm::ES256 => "ES256",
    Algorithm::ES384 => "ES384",
    Algorithm::RS256 => "RS256",
    Algorithm::RS384 => "RS384",
    Algorithm::PS256 => "PS256",
    Algorithm::PS384 => "PS384",
    Algorithm::PS512 => "PS512",
    Algorithm::RS512 => "RS512",
  }
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
