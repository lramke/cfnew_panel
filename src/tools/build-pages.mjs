import { build } from 'esbuild';
import { mkdir, readFile, writeFile, rm, copyFile } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';

const panel = fileURLToPath(new URL('../', import.meta.url));
const destination = resolve(process.argv[2] || join(panel, '..', 'dist/pages'));
const assets = join(destination, 'assets');

await rm(destination, { recursive: true, force: true });
await mkdir(assets, { recursive: true });

const version = (await readFile(join(panel, 'release.mjs'), 'utf8')).match(/PANEL_VERSION = '([^']+)'/)[1];

const shims = {
  'node:fs': join(panel, 'web/shims/fs.mjs'),
  'node:zlib': join(panel, 'web/shims/zlib.mjs'),
  'node:crypto': join(panel, 'web/shims/crypto.mjs'),
  'node:net': join(panel, 'web/shims/net.mjs'),
};

await build({
  entryPoints: [join(panel, 'web/static-panel.js')],
  outfile: join(assets, 'panel.js'),
  bundle: true,
  platform: 'browser',
  format: 'esm',
  target: ['es2022'],
  minify: true,
  charset: 'utf8',
  legalComments: 'none',
  sourcemap: false,
  plugins: [{
    name: 'node-shims',
    setup(builder) {
      builder.onResolve({ filter: /^node:(fs|zlib|crypto|net)$/ }, args => ({ path: shims[args.path] }));
    },
  }],
});

await copyFile(join(panel, 'theme.css'), join(assets, 'theme.css'));
await writeFile(join(assets, 'singbox-rules.json'), gunzipSync(await readFile(join(panel, 'singbox-rules.json.gz'))));
await writeFile(join(destination, '.nojekyll'), '');
await writeFile(join(destination, 'robots.txt'), 'User-agent: *\nDisallow: /\n');

let landing = await readFile(join(panel, 'index.html'), 'utf8');
landing = landing
  .replace('__CFNEW_PANEL_VERSION__', version)
  .replace('action="/panel"', 'action="panel.html"')
  .replace('订阅从本服务更新。', '订阅在浏览器内生成并下载。')
  .replace('</head>', '<link rel="stylesheet" href="assets/theme.css">\n</head>')
  .replace('<small id="panelVersion">', '<div class="landing-note"><strong>GitHub Pages 静态版</strong>：配置直接保存到你的 Worker；订阅以配置文件下载，无法提供自动更新的订阅链接。需要完整订阅服务请部署 Vercel 或 Docker 后端。</div>\n  <small id="panelVersion">');
await writeFile(join(destination, 'index.html'), landing);

const mark = '<div class="brand-mark brand-mark-lg" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><g stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M24 6.5v35"/><path d="M6.5 24h35"/><path d="M11.6 11.6l24.8 24.8"/><path d="M36.4 11.6L11.6 36.4"/><path d="M32.8 8.8L24 24"/><path d="M39.2 15.2L24 24"/><path d="M39.2 32.8L24 24"/><path d="M32.8 39.2L24 24"/><path d="M15.2 39.2L24 24"/><path d="M8.8 32.8L24 24"/><path d="M8.8 15.2L24 24"/><path d="M15.2 8.8L24 24"/></g></svg></div>';

const panelShell = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f0eee6">
<meta name="description" content="CFnew 控制台 · GitHub Pages 静态版">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cg stroke='%23c96442' stroke-width='4' stroke-linecap='round'%3E%3Cpath d='M24 6v36M6 24h36M11 11l26 26M37 11L11 37'/%3E%3C/g%3E%3C/svg%3E">
<link rel="stylesheet" href="assets/theme.css">
<title>CFnew 控制台</title>
</head>
<body class="landing">
<main id="app">
  <div class="header">
    ${mark}
    <h1 class="title">正在连接</h1>
    <p class="subtitle">读取 Worker 配置…</p>
  </div>
  <div class="card">
    <p class="subtitle">首次加载会直接连接你的 Worker，请稍候。</p>
    <noscript><p class="subtitle">静态面板需要启用 JavaScript。</p></noscript>
  </div>
</main>
<script type="module" src="assets/panel.js"></script>
</body>
</html>
`;
await writeFile(join(destination, 'panel.html'), panelShell);

const notFound = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f0eee6">
<link rel="stylesheet" href="assets/theme.css">
<title>页面不存在 · CFnew</title>
</head>
<body class="landing">
<main>
  <div class="header">
    ${mark}
    <h1 class="title">页面不存在</h1>
    <p class="subtitle">这个地址没有对应的静态页面。</p>
  </div>
  <div class="card"><a href="./">返回面板首页</a></div>
</main>
</body>
</html>
`;
await writeFile(join(destination, '404.html'), notFound);

console.log('GitHub Pages 静态包已生成：' + destination);
console.log('内容：index.html、panel.html、404.html、assets/panel.js、assets/theme.css、assets/singbox-rules.json');
