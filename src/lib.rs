use neon::prelude::*;

mod sign;
mod utils;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("sign", sign::sign)?;
    Ok(())
}
