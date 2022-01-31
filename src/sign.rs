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
  let payload = cx.argument::<JsObject>(0)?;
  let key = cx.argument::<JsString>(1)?.value(&mut cx);
  let options = cx
    .argument_opt(2)
    .unwrap_or(cx.empty_object().downcast_or_throw::<JsValue, _>(&mut cx)?)
    .downcast_or_throw::<JsObject, _>(&mut cx)?;

  let payload_json = to_json(&mut cx, payload)?.value(&mut cx);
  let mut claims: Claims = serde_json::from_str(payload_json.as_str()).unwrap();

  let options_json = to_json(&mut cx, options)?.value(&mut cx);
  let sign_options: SignOptions = serde_json::from_str(options_json.as_str()).unwrap();

  sign_options.parse_options(&mut claims);

  let encoding_key = match sign_options.header.unwrap_or(Header::default()).alg {
    Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
      EncodingKey::from_secret(key.as_bytes())
    }
    Algorithm::RS256
    | Algorithm::RS384
    | Algorithm::RS512
    | Algorithm::PS256
    | Algorithm::PS384
    | Algorithm::PS512 => EncodingKey::from_rsa_pem(key.as_bytes()).unwrap(),
    Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(key.as_bytes()).unwrap(),
  };

  let token = encode(&Header::default(), &claims, &encoding_key).unwrap();

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
