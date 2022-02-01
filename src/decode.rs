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

trait ToObject {
  fn to_object<'a>(self, cx: &mut FunctionContext<'a>) -> Handle<'a, JsObject>;
}

impl ToObject for jsonwebtoken::Header {
  fn to_object<'a>(self, cx: &mut FunctionContext<'a>) -> Handle<'a, JsObject> {
    let mut header = cx.empty_object();

    let alg = cx.string(alg_to_string(self.alg));
    header.set(cx, "alg", alg).unwrap();
    header.set_optional(cx, "cty", self.cty).unwrap();
    header.set_optional(cx, "jku", self.jku).unwrap();
    header.set_optional(cx, "kid", self.kid).unwrap();
    header.set_optional(cx, "typ", self.typ).unwrap();
    header.set_optional(cx, "x5t", self.x5t).unwrap();
    header.set_optional(cx, "x5u", self.x5u).unwrap();

    header
  }
}

trait SetOptional {
  fn set_optional<'a>(
    &mut self,
    cx: &mut FunctionContext<'a>,
    key: &str,
    value: Option<String>,
  ) -> NeonResult<()>;
}

impl SetOptional for neon::prelude::JsObject {
  fn set_optional<'a>(
    &mut self,
    cx: &mut FunctionContext<'a>,
    key: &str,
    value: Option<String>,
  ) -> NeonResult<()> {
    if value.is_some() {
      let js_string = cx.string(value.unwrap());
      self.set(cx, key, js_string).unwrap(); 
    }
    Ok(())
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
