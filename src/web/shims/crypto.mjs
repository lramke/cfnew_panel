// 浏览器端 node:crypto 兼容：仅实现引擎使用的 MD5 摘要。
const shifts = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const constants = new Uint32Array(64);
for (let index = 0; index < 64; index++) constants[index] = Math.floor(Math.abs(Math.sin(index + 1)) * 2 ** 32);

function md5(bytes) {
  const length = bytes.length;
  const bitLength = length * 8;
  const padded = (((length + 8) >> 6) + 1) << 6;
  const buffer = new Uint8Array(padded);
  buffer.set(bytes);
  buffer[length] = 0x80;
  const view = new DataView(buffer.buffer);
  view.setUint32(padded - 8, bitLength >>> 0, true);
  view.setUint32(padded - 4, Math.floor(bitLength / 2 ** 32), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const words = new Uint32Array(16);
  for (let offset = 0; offset < padded; offset += 64) {
    for (let index = 0; index < 16; index++) words[index] = view.getUint32(offset + index * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let index = 0; index < 64; index++) {
      let f, g;
      if (index < 16) { f = (b & c) | (~b & d); g = index; }
      else if (index < 32) { f = (d & b) | (~d & c); g = (5 * index + 1) % 16; }
      else if (index < 48) { f = b ^ c ^ d; g = (3 * index + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * index) % 16; }
      f = (f + a + constants[index] + words[g]) >>> 0;
      a = d;
      d = c;
      c = b;
      const shift = shifts[index];
      b = (b + ((f << shift) | (f >>> (32 - shift)))) >>> 0;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const out = new DataView(new ArrayBuffer(16));
  out.setUint32(0, a0, true);
  out.setUint32(4, b0, true);
  out.setUint32(8, c0, true);
  out.setUint32(12, d0, true);
  return [...new Uint8Array(out.buffer)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export function createHash(algorithm) {
  if (algorithm !== 'md5') throw new Error('浏览器构建仅支持 md5');
  let data = '';
  return {
    update(value) { data += String(value); return this; },
    digest(encoding) {
      const hex = md5(new TextEncoder().encode(data));
      return encoding === 'hex' || encoding === undefined ? hex : hex;
    },
  };
}
