use crate::utils::to_json;
use jsonwebtoken::encode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::{EncodingKey, Header};
use neon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub fn sign(mut cx: FunctionContext) -> JsResult<JsString> {
  let payload: Handle<JsObject> = cx.argument(0)?;
  let key = cx.argument::<JsString>(1)?.value(&mut cx);
  // let options = cx
  //   .argument_opt(2)
  //   .unwrap()
  //   .downcast_or_throw::<JsObject, _>(&mut cx)?;

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

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  #[serde(default = "default_iat")]
  iat: u64,
  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

fn default_iat() -> u64 {
  let start = SystemTime::now();
  let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();

  since_the_epoch.as_secs()
}

#[derive(Debug, Serialize, Deserialize)]
struct SignOptions {
  /// (default: HS256)
  algorithm: Option<Algorithm>,
  /// expressed in seconds or a string describing a time span vercel/ms.
  /// Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").
  expiresIn: Option<u64>,

  /// expressed in seconds or a string describing a time span vercel/ms.
  /// Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").
  notBefore: Option<u64>,
  audience: Option<String>,
  issuer: Option<String>,
  jwtid: Option<String>,
  subject: Option<String>,
  noTimestamp: Option<bool>,
  header: Option<Header>,
  keyid: Option<String>,
}
