use crate::jsonwebtoken_mod::algorithm::AsStr;
use neon::prelude::*;

pub trait ToObject {
  fn to_object<'a>(self, cx: &mut FunctionContext<'a>) -> Handle<'a, JsObject>;
}

impl ToObject for jsonwebtoken::Header {
  fn to_object<'a>(self, cx: &mut FunctionContext<'a>) -> Handle<'a, JsObject> {
    let header = cx.empty_object();
    let set_optional = |cx: &mut FunctionContext, key: &str, value: Option<&String>| -> NeonResult<()> {
      if value.is_some() {
        let js_string = cx.string(value.unwrap());
        header.set(cx, key, js_string).unwrap();
      }
      Ok(())
    };

    let alg = cx.string(self.alg.as_str());
    header.set(cx, "alg", alg).unwrap();
    set_optional(cx, "cty", self.cty.as_ref()).unwrap();
    set_optional(cx, "jku", self.jku.as_ref()).unwrap();
    set_optional(cx, "kid", self.kid.as_ref()).unwrap();
    set_optional(cx, "typ", self.typ.as_ref()).unwrap();
    set_optional(cx, "x5t", self.x5t.as_ref()).unwrap();
    set_optional(cx, "x5u", self.x5u.as_ref()).unwrap();

    header
  }
}
