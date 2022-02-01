use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

pub trait AsStr {
  fn as_str(&self) -> &str;
}

impl AsStr for Algorithm {
  fn as_str(&self) -> &str {
    match self {
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
}

pub trait Key {
  fn get_encoding_key(self, key: &[u8]) -> EncodingKey;
  fn get_decoding_key(self, key: &[u8]) -> DecodingKey;
}

impl Key for Algorithm {
  fn get_encoding_key(self, key: &[u8]) -> EncodingKey {
    match self {
      Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => EncodingKey::from_secret(key),
      Algorithm::RS256
      | Algorithm::RS384
      | Algorithm::RS512
      | Algorithm::PS256
      | Algorithm::PS384
      | Algorithm::PS512 => EncodingKey::from_rsa_pem(key).unwrap(),
      Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(key).unwrap(),
    }
  }

  fn get_decoding_key(self, key: &[u8]) -> DecodingKey {
    match self {
      Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => DecodingKey::from_secret(key),
      Algorithm::RS256
      | Algorithm::RS384
      | Algorithm::RS512
      | Algorithm::PS256
      | Algorithm::PS384
      | Algorithm::PS512 => DecodingKey::from_rsa_pem(key).unwrap(),
      Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(key).unwrap(),
    }
  }
}
