use neon::prelude::*;

pub fn to_json<'a>(cx: &mut FunctionContext<'a>, obj: Handle<JsObject>) -> JsResult<'a, JsString> {
  let null = cx.null();
  let json = cx
    .global()
    .get(cx, "JSON")?
    .downcast_or_throw::<JsObject, _>(cx)?;
  let stringify = json
    .get(cx, "stringify")?
    .downcast_or_throw::<JsFunction, _>(cx)?;

  let json_string = stringify
    .call(cx, null, vec![obj])?
    .downcast_or_throw::<JsString, _>(cx)?;

  Ok(json_string)
}
