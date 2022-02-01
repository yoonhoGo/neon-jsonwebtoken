use crate::jsonwebtoken_mod::algorithm::Key;
use crate::neon_serde;
use crate::utils::now;
use jsonwebtoken::{encode, Algorithm, Header};
use neon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub fn sign(mut cx: FunctionContext) -> JsResult<JsString> {
  let payload = cx.argument::<JsValue>(0)?;
  let key = cx.argument::<JsString>(1)?.value(&mut cx);
  let options = cx.argument_opt(2);

  let mut claims: Claims = neon_serde::from_value(&mut cx, payload).unwrap();
  let sign_options: SignOptions =
    neon_serde::from_value_opt(&mut cx, options).unwrap_or(SignOptions::default());
  sign_options.parse_options(&mut claims);

  let encoding_key = sign_options
    .header
    .unwrap_or(Header::default())
    .alg
    .get_encoding_key(key.as_bytes());

  let token = encode(&Header::default(), &claims, &encoding_key).unwrap();

  Ok(cx.string(token))
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
  #[serde(default = "now")]
  iat: u64,
  #[serde(flatten)]
  extra: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignOptions {
  /// (default: HS256)
  algorithm: Option<Algorithm>,
  /// expressed in seconds or a string describing a time span vercel/ms.
  /// Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").
  expires_in: Option<u64>,

  /// expressed in seconds or a string describing a time span vercel/ms.
  /// Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").
  not_before: Option<u64>,
  audience: Option<String>,
  issuer: Option<String>,
  jwtid: Option<String>,
  subject: Option<String>,
  no_timestamp: Option<bool>,
  header: Option<Header>,
  keyid: Option<String>,
}

impl SignOptions {
  fn insert_claim(&self, claims: &mut Claims, key: &str, value: &Option<String>) {
    if value.is_some() {
      claims.extra.insert(
        key.to_string(),
        serde_json::Value::from(value.as_ref().unwrap().to_string()),
      );
    }
  }
  fn insert_claim_u64(&self, claims: &mut Claims, key: &str, value: Option<u64>) {
    if value.is_some() {
      claims
        .extra
        .insert(key.to_string(), serde_json::Value::from(value.unwrap()));
    }
  }

  fn parse_options(&self, claims: &mut Claims) {
    self.insert_claim_u64(claims, "exp", self.expires_in);
    self.insert_claim_u64(claims, "nbf", self.not_before);
    self.insert_claim(claims, "aud", &self.audience);
    self.insert_claim(claims, "iss", &self.issuer);
    self.insert_claim(claims, "jti", &self.jwtid);
    self.insert_claim(claims, "sub", &self.subject);
  }
}

impl Default for SignOptions {
  fn default() -> Self {
    SignOptions {
      algorithm: Some(Algorithm::HS256),
      expires_in: None,
      not_before: None,
      audience: None,
      issuer: None,
      jwtid: None,
      subject: None,
      no_timestamp: None,
      header: None,
      keyid: None,
    }
  }
}
