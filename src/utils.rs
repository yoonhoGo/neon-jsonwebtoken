use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
  let start = SystemTime::now();
  let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();

  since_the_epoch.as_secs()
}
