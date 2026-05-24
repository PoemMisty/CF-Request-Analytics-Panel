import worker from "../src/worker.js";

export function onRequest(context) {
  return worker.fetch(context.request, context.env, context);
}
