// 浏览器端 node:zlib 兼容：静态面板启动时预取并解压好的规则文本。
export function gunzipSync() {
  const text = globalThis.__CFNEW_RULES_TEXT__;
  if (!text) throw new Error('分流规则尚未加载，请稍后重试');
  return text;
}
