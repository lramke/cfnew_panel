// 浏览器端 node:fs 兼容：规则文件由构建脚本预解压并单独提供。
export function readFileSync() {
  return new Uint8Array(0);
}

export function readFile() {
  return Promise.resolve('');
}
