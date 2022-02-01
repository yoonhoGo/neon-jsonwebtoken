#[macro_use]
extern crate error_chain;
extern crate neon;
extern crate num;
#[macro_use]
extern crate serde;

use neon::prelude::*;

mod decode;
mod neon_serde;
mod sign;
mod utils;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("sign", sign::sign)?;
    cx.export_function("decode", decode::decode)?;
    Ok(())
}
