import { createSubscriptionEngine } from '../engine.mjs';
import { coreRelease } from '../release.mjs';

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fakeOrigin = 'https://cfnew-static.invalid';

function safeJson(value) {
  return JSON.stringify(value)
    .replaceAll('<', '\\u003c')
    .replaceAll(String.fromCharCode(0x2028), '\\u2028')
    .replaceAll(String.fromCharCode(0x2029), '\\u2029');
}

function normalizeHost(value) {
  const text = String(value || '').trim();
  if (!text) throw new Error('缺少 Worker 域名');
  const url = new URL(/^https?:\/\//i.test(text) ? text : 'https://' + text);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || url.search || url.hash) throw new Error('请输入 Worker 域名');
  if (url.pathname !== '/' && url.pathname !== '') throw new Error('域名中不要带路径');
  if (!local && (url.protocol !== 'https:' || (url.port && url.port !== '443'))) throw new Error('Worker 须使用 HTTPS');
  if (!['https:', 'http:'].includes(url.protocol)) throw new Error('请输入 Worker 域名');
  return url.origin;
}

function normalizeAccess(value) {
  const access = String(value || '').trim().replace(/^\/+|\/+$/g, '');
  if (!access || access.length > 2048 || /[?#\\\u0000-\u0020\u007f]/.test(access)) throw new Error('请填写 UUID 或自定义路径');
  let decoded;
  try { decoded = decodeURIComponent(access); } catch { throw new Error('自定义路径格式无效'); }
  if (/[?#\\\u0000-\u0020\u007f]/.test(decoded) || decoded.split('/').some(part => part === '.' || part === '..')) throw new Error('自定义路径格式无效');
  return uuidPattern.test(access) ? access.toLowerCase() : new URL('/' + access, 'https://path.invalid').pathname.slice(1);
}

function renderError(message) {
  document.body.className = 'landing';
  const main = document.createElement('main');
  const header = document.createElement('div');
  header.className = 'header';
  const mark = document.createElement('div');
  mark.className = 'brand-mark brand-mark-lg';
  mark.setAttribute('aria-hidden', 'true');
  mark.innerHTML = '<svg viewBox="0 0 48 48" fill="none"><g stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M24 6.5v35"/><path d="M6.5 24h35"/><path d="M11.6 11.6l24.8 24.8"/><path d="M36.4 11.6L11.6 36.4"/></g></svg>';
  const title = document.createElement('h1');
  title.className = 'title';
  title.textContent = '连接未完成';
  header.append(mark, title);
  const card = document.createElement('div');
  card.className = 'card';
  const text = document.createElement('p');
  text.className = 'subtitle';
  text.style.textAlign = 'left';
  text.textContent = message;
  const back = document.createElement('a');
  back.href = 'index.html';
  back.textContent = '返回重新填写';
  back.style.display = 'inline-block';
  back.style.marginTop = '18px';
  card.append(text, back);
  main.append(header, card);
  document.body.replaceChildren(main);
}

// 注入到引擎页面末尾的静态运行时。只依赖 window 上的对象，便于序列化。
function installStaticBoot() {
  const state = window.__CFNEW_STATIC__;
  const CFNEW = window.CFNEW;
  const fakeOrigin = 'https://cfnew-static.invalid';
  const originalFetch = window.fetch.bind(window);

  function toast(message, type) {
    try { window.显示提示(message, type || 'info'); } catch {}
  }

  function needsRules(target) {
    return /^sing-?box$/i.test(String(target || ''));
  }

  let rulesPromise = null;
  async function ensureRules() {
    if (globalThis.__CFNEW_RULES_TEXT__) return;
    if (!rulesPromise) {
      rulesPromise = originalFetch(new URL('assets/singbox-rules.json', location.href), { cache: 'force-cache' })
        .then(response => {
          if (!response.ok) throw new Error('HTTP ' + response.status);
          return response.text();
        })
        .then(text => { globalThis.__CFNEW_RULES_TEXT__ = text; })
        .catch(error => { rulesPromise = null; throw error; });
    }
    try {
      await rulesPromise;
    } catch (error) {
      throw new Error('分流规则加载失败：' + (error && error.message ? error.message : error) + '，请刷新页面重试');
    }
  }

  function buildRequest(target) {
    return new Request(state.workerBase + '/' + state.uuid + '/sub?target=' + encodeURIComponent(target || 'base64'));
  }

  // 静态模式提示
  const container = document.querySelector('.container');
  if (container) {
    const notice = document.createElement('aside');
    notice.className = 'static-notice';
    const strong = document.createElement('strong');
    strong.textContent = 'GitHub Pages 静态模式';
    notice.append(strong, document.createTextNode(' · 配置直接保存到你的 Worker；订阅在浏览器内生成并下载，无法提供自动更新的订阅链接。需要订阅链接请部署 Vercel 或 Docker 完整后端。下载的订阅文件包含 UUID，请勿公开分享。'));
    container.insertBefore(notice, container.firstChild);
  }
  document.body.classList.add('static-mode');

  // 内核版本提示
  const release = CFNEW.release;
  if (release && release.needsUpdate) {
    const section = document.createElement('section');
    section.id = 'coreVersionStatus';
    const strong = document.createElement('strong');
    strong.textContent = '内核需要更新';
    const versions = document.createElement('div');
    versions.textContent = '面板版本 ' + release.panelVersion + ' · 内核版本 ' + (release.coreVersion || '未标版本（旧内核）');
    const hint = document.createElement('p');
    hint.textContent = '当前内核与面板版本不一致。请上传配套内核，保留原来的 u 和 C/c 绑定，然后刷新此页。';
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = '本次更新了什么';
    const list = document.createElement('ul');
    for (const item of release.changes || []) {
      const li = document.createElement('li');
      li.textContent = item;
      list.append(li);
    }
    const downloads = document.createElement('div');
    downloads.className = 'release-downloads';
    for (const [label, href] of [['下载 pages.zip', release.zipUrl], ['下载 _worker.js', release.workerUrl]]) {
      const link = document.createElement('a');
      link.textContent = label;
      link.href = href;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      downloads.append(link);
    }
    details.append(summary, list, downloads);
    section.append(strong, versions, hint, details);
    document.body.prepend(section);
  }

  // 静态模式没有服务端：拦截优选接口与本地面板订阅地址。
  window.fetch = async function (input, init) {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (raw.startsWith(fakeOrigin + '/api/preferred/')) {
      const action = raw.slice(raw.lastIndexOf('/') + 1).split('?')[0];
      let data = {};
      try { data = JSON.parse((init && init.body) || '{}'); } catch {}
      if (action === 'probe') {
        return Response.json({ success: false, latency: -1, colo: '', error: '静态模式无法在浏览器内检测 IP 可用性，请在客户端测速。' });
      }
      if (action === 'list') {
        if (!data.url) return new Response('', { status: 400, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        try {
          const response = await originalFetch(data.url, { headers: { Accept: 'text/plain' } });
          if (!response.ok) throw new Error('HTTP ' + response.status);
          return new Response(await response.text(), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        } catch (error) {
          toast('列表来源需要允许跨域访问：' + error.message, 'warn');
          return new Response('', { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
        }
      }
    }
    if (raw.startsWith(fakeOrigin + '/sub')) {
      const target = new URL(raw).searchParams.get('target') || 'base64';
      try {
        if (needsRules(target)) await ensureRules();
        return await state.engine.subscribe(buildRequest(target));
      } catch (error) {
        return new Response('订阅生成失败：' + error.message, { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }
    }
    return originalFetch(input, init);
  };

  function fileMeta(type) {
    const value = String(type || '').toLowerCase();
    if (value === 'singbox' || value === 'sing-box') return { ext: 'json', mime: 'application/json' };
    if (value === 'clash' || value === 'stash' || value === 'vg') return { ext: 'yaml', mime: 'text/yaml' };
    return { ext: 'txt', mime: 'text/plain' };
  }

  function fileSlug(name) {
    return String(name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'subscription';
  }

  window.生成客户端链接 = async function (type, name) {
    const label = name || type;
    const box = document.getElementById('clientSubscriptionUrl');
    try {
      if (needsRules(type)) await ensureRules();
      const response = await state.engine.subscribe(buildRequest(type));
      const text = await response.text();
      if (!response.ok) throw new Error(text || ('HTTP ' + response.status));
      const meta = fileMeta(type);
      const blob = new Blob([text], { type: meta.mime + ';charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'cfnew-' + fileSlug(label) + '.' + meta.ext;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      if (box) {
        box.textContent = '已下载 ' + label + ' 配置文件。静态模式不能提供自动更新的订阅链接。';
        box.style.display = 'block';
      }
      toast(label + ' 配置文件已生成', 'success');
    } catch (error) {
      if (box) {
        box.textContent = '生成失败：' + error.message;
        box.style.display = 'block';
      }
      toast('生成失败：' + error.message, 'error');
    }
  };
}

async function main() {
  const params = new URLSearchParams(location.search);
  let workerBase, access;
  try {
    workerBase = normalizeHost(params.get('host'));
    access = normalizeAccess(params.get('uuid'));
  } catch (error) {
    renderError(error.message);
    return;
  }

  let configResponse;
  try {
    const signal = typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(15000) : undefined;
    configResponse = await fetch(workerBase + '/' + access + '/api/config', { headers: { Accept: 'application/json' }, signal });
  } catch (error) {
    renderError('读取 Worker 配置失败：' + (error && error.message ? error.message : error) + '。静态模式要求内核允许跨域读取；请确认域名、UUID 或自定义路径正确。');
    return;
  }
  if (!configResponse.ok) {
    let detail = 'HTTP ' + configResponse.status;
    try {
      const body = await configResponse.json();
      if (body && body.message) detail = body.message;
    } catch {}
    renderError('读取 Worker 配置失败：' + detail + '。请确认域名、UUID 或自定义路径和核心版本。');
    return;
  }

  let config;
  try { config = await configResponse.json(); } catch { renderError('Worker 返回的配置不是有效 JSON。'); return; }
  if (!config || Array.isArray(config) || typeof config !== 'object' || typeof config.kvEnabled !== 'boolean') {
    renderError('该地址没有兼容的配置接口，请确认 Worker 内核版本。');
    return;
  }
  const resolvedUuid = typeof config.uuid === 'string' ? config.uuid.toLowerCase() : uuidPattern.test(access) ? access : '';
  if (!uuidPattern.test(resolvedUuid)) {
    renderError('请更新精简内核后再使用自定义路径登录。');
    return;
  }

  // 自定义入口解析成稳定 UUID 后，同步本地记录和地址栏。
  try {
    const nodes = JSON.parse(localStorage.getItem('cfnew-panel-nodes') || '[]');
    if (Array.isArray(nodes)) {
      for (const node of nodes) {
        if (!node || typeof node.host !== 'string') continue;
        try {
          const origin = new URL(/^https?:\/\//i.test(node.host) ? node.host : 'https://' + node.host).origin;
          if (origin === workerBase && node.uuid === access) node.uuid = resolvedUuid;
        } catch {}
      }
      localStorage.setItem('cfnew-panel-nodes', JSON.stringify(nodes));
    }
  } catch {}
  if (access !== resolvedUuid) {
    const stable = new URL(location.href);
    stable.searchParams.set('uuid', resolvedUuid);
    history.replaceState(null, '', stable.href);
  }

  let savedLanguage = params.get('lang') || '';
  if (!savedLanguage) {
    try { savedLanguage = localStorage.getItem('preferredLanguage') || ''; } catch {}
  }
  savedLanguage = ['fa', 'fa-IR'].includes(savedLanguage) ? 'fa' : ['zh', 'zh-CN'].includes(savedLanguage) ? 'zh' : '';
  const renderHeaders = { 'Accept-Language': navigator.language || 'zh-CN' };
  if (savedLanguage) renderHeaders.Cookie = 'preferredLanguage=' + savedLanguage;

  const engine = createSubscriptionEngine({ ...config, uuid: resolvedUuid }, resolvedUuid);
  const rendered = await (await engine.render(new Request(workerBase + '/' + resolvedUuid, {
    headers: renderHeaders,
  }))).text();

  const context = {
    host: workerBase,
    uuid: resolvedUuid,
    apiBase: workerBase + '/' + resolvedUuid,
    subPath: '',
    config,
    release: coreRelease(config),
    staticMode: true,
    preferredApiBase: fakeOrigin,
    subUrl: fakeOrigin + '/sub?uuid=' + resolvedUuid,
    subDisplayUrl: '静态模式：请在「选择客户端」中下载配置文件',
    subDisplayHref: '#',
  };

  window.__CFNEW_STATIC__ = { engine, workerBase, uuid: resolvedUuid };

  const themeHref = new URL('assets/theme.css', location.href).href;
  const boot = '<script>(' + installStaticBoot.toString() + ')();<' + '/script>';
  const head = '<link rel="stylesheet" href="' + themeHref + '"><script>window.CFNEW=' + safeJson(context) + ';<' + '/script>';
  const html = rendered
    .replace('<head>', () => '<head>' + head)
    .replace('</body>', () => boot + '</body>');

  document.open();
  document.write(html);
  document.close();
}

main().catch(error => renderError('页面初始化失败：' + (error && error.message ? error.message : error)));
