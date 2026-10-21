// 浏览器端 node:net 兼容：仅实现引擎使用的 isIP。
const ipv4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIP(value) {
  const text = String(value ?? '');
  if (ipv4.test(text)) return 4;
  if (!text.includes(':')) return 0;
  try {
    const url = new URL('http://[' + text + ']/');
    return url.hostname.startsWith('[') ? 6 : 0;
  } catch {
    return 0;
  }
}
