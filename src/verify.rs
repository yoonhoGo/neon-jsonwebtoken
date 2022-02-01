use crate::jsonwebtoken_mod::algorithm::Key;
use crate::jsonwebtoken_mod::header::ToObject;
use crate::neon_serde;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use neon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub fn verify(mut cx: FunctionContext) -> JsResult<JsValue> {
  let jwt = cx.argument::<JsString>(0)?.value(&mut cx);
  let key = cx.argument::<JsString>(1)?.value(&mut cx);
  let options = cx.argument_opt(2);
  let decode_options: VerifyOptions =
    neon_serde::from_value_opt(&mut cx, options).unwrap_or(VerifyOptions::default());

  let validation = decode_options.to_validation();
  let key = decode_options.get_key(key.as_bytes());

  let payload = decode::<Claims>(&jwt, &key, &validation).unwrap();

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
#[serde(rename_all = "camelCase")]
struct VerifyOptions {
  algorithms: Vec<Algorithm>,
  audience: Option<Vec<String>>,
  complete: Option<bool>,
  issuer: Option<String>,
  jwtid: Option<String>,
  ignore_expiration: Option<bool>,
  ignore_not_before: Option<bool>,
  subject: Option<String>,
}

impl VerifyOptions {
  fn to_validation(&self) -> Validation {
    let mut validation = Validation {
      algorithms: self.algorithms.clone(),
      iss: self.issuer.clone(),
      sub: self.subject.clone(),
      validate_exp: self.ignore_expiration.unwrap_or(true),
      validate_nbf: self.ignore_not_before.unwrap_or(false),
      ..Default::default()
    };

    if self.audience.is_some() {
      validation.set_audience(&self.audience.clone().unwrap().as_slice());
    }

    validation
  }

  fn get_key<'a>(&self, key: &'a [u8]) -> DecodingKey<'a> {
    for alg in &self.algorithms {
      return alg.get_decoding_key(key);
    }

    DecodingKey::from_secret(key)
  }
}

impl Default for VerifyOptions {
  fn default() -> Self {
    VerifyOptions {
      algorithms: vec![Algorithm::HS256],
      audience: None,
      complete: Some(false),
      issuer: None,
      jwtid: None,
      ignore_expiration: Some(true),
      ignore_not_before: Some(false),
      subject: None,
    }
  }
}
