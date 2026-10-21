# CFnew 独立面板

[![部署到 Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FbyJoey%2Fcfnew-panel&project-name=cfnew-panel&repository-name=cfnew-panel)
[![Node.js 22](https://img.shields.io/badge/Node.js-22-43853d)](https://nodejs.org/)
[![源码许可](https://img.shields.io/badge/源码许可-署名与禁止冒充原创-blue)](./LICENSE)

把 CFnew 控制台、优选操作和订阅生成放在 Vercel，Cloudflare Worker 只负责代理转发和 KV 配置。节点流量直接连接你自己的 Worker，不经过面板。

图文教程：[CFnew 独立面板：Vercel 一键部署](https://joeyblog.net/cfnew-panel-vercel-deploy.html)。

界面采用 Claude 风格：暖白纸面、墨色文字、陶土橙强调色，衬线标题，并跟随系统切换深色模式。控制台与登录页共用 [`src/theme.css`](./src/theme.css)。

## 一键部署

1. 先部署 [CFnew 精简内核](https://github.com/byJoey/cfnew/tree/core-only)，设置 Worker 变量 `u` 为自己的 UUID。需要在线保存配置时，绑定 KV，名称填 `C` 或 `c`。已有用户保留原 UUID 和 KV 绑定，兼容日期用 `2026-01-20`。
2. 点击上面的 Deploy 按钮，登录 Vercel，按页面提示连接 GitHub 并创建自己的仓库副本。
3. Application Preset（旧界面叫 Framework）选择 **Other**；如果自动识别成 Node，请改为 Other。根目录保持仓库根目录，无需手填构建命令。点击 Deploy，等待完成。
4. 打开分配的面板域名，填写自己的 Worker 域名与 UUID 或自定义路径，即可连接。
5. 在面板中配置并复制订阅到客户端。订阅使用面板域名；节点的 SNI / Host 与代理入口仍是 Worker。

部署按钮会引导平台登录、Git 授权和创建项目，这些步骤仍需用户在自己的账号完成。项目无需付费数据库或面板 KV。

如果仓库列表为空，先到 Vercel 账号的 Authentication → Sign-in Methods 连接 GitHub，再返回部署页面。

GitHub 中已经有自己的 `cfnew-panel` 仓库时，在 Vercel 的 New Project → Import Git Repository 选择该仓库即可。通过 Git 连接部署后，推送到 `main` 会自动更新正式站；其它分支用于预览。已有源码无需删掉重建。

## 可选变量：w

`w` 设置在 **Vercel 面板项目**的 Settings → Environment Variables，变量名为小写。选择 Production；需要预览也生效时同时选择 Preview。保存后重新部署。

| w 的值 | 入口与行为 |
| --- | --- |
| 不设置或留空 | 公共面板。首页显示 Worker 域名和 UUID / 自定义路径连接表单，可接入任意兼容 Worker。 |
| `https://your-worker.example.com` | 只管理这个 Worker。首页返回 `hello`，不显示连接表单；通过 `https://面板域名/UUID` 或自定义路径进入原控制台。 |

只填 Worker 的 HTTPS 根地址，不带 UUID、路径或查询参数。HTTPS 前缀可省略。无效值会拒绝连接；填写后不能通过换查询参数接入其它 Worker。

`w` 不需要写到 Worker 内核里，也不代替 UUID 验证。面板不能凭这个变量替你隐藏 Worker 的全部网络路径。

固定 Worker 后：

```text
控制台：https://面板域名/你的UUID
订阅：  https://面板域名/你的UUID/sub
Clash： https://面板域名/你的UUID/sub?target=clash
```

如果 Worker 的 `d` 是 `/Admin/Panel`，也可用 `https://面板域名/Admin/Panel` 进入。大小写必须一致。登录后地址自动使用稳定的 UUID，后续修改 `d` 不影响当前面板重载和已复制订阅。`d` 是配置入口，`tp` 是代理传输设置。

## 让订阅客户端能访问

先用未登录 Vercel 的浏览器打开面板。若被 Vercel 登录页拦住，在 Settings → Deployment Protection 调整 Vercel Authentication，使使用中的部署域名可公开访问。

浏览器登录 Vercel 后能打开面板，不代表客户端能更新订阅。用实际对外域名验证，不能给订阅链接附上 Vercel 账号令牌。

## 公共模式

首页填写域名和 UUID 即可。也可使用：

```text
控制台：/panel?host=your-worker.example.com&uuid=你的UUID
订阅：  /sub?host=your-worker.example.com&uuid=你的UUID
Clash： /sub?host=your-worker.example.com&uuid=你的UUID&target=clash
```

支持 `base64`、`v2ray`、`clash`、`stash`、`singbox`、`surge`、`loon`、`quanx`；开启家宽链式后可使用 `target=vg`。不指定时按客户端请求头识别。

未绑定 Worker KV 仍可读取环境配置并生成订阅，但页面不能保存。原来直接指向 Worker 的 `/sub` 需替换成独立面板生成的新订阅。

## 部署到 GitHub Pages（静态版）

仓库内置 `.github/workflows/pages.yml`，可以把面板作为纯静态站点发布到 GitHub Pages。适合只想在浏览器里管理配置、并手动导入订阅文件的场景。

1. 把仓库推送到自己的 GitHub 账号，默认分支保持 `main`。
2. 打开仓库 Settings → Pages → Build and deployment，把 Source 选为 **GitHub Actions**（首次运行工作流也会尝试自动启用 Pages）。
3. 推送到 `main`，或手动运行 `Deploy GitHub Pages` 工作流。完成后站点地址为 `https://你的用户名.github.io/仓库名/`。
4. 首页填写 Worker 域名与 UUID 或自定义路径即可进入控制台。

静态版的工作方式：

- 浏览器直接请求 `https://你的Worker/.../api/config`，保存配置也直接写回 Worker，不经过第三方服务器。配套精简内核已带跨域响应头；旧内核不支持跨域时，静态版会提示读取失败。
- 登录、读取与保存配置、生成各客户端配置都可用。
- **订阅以文件下载**：选择客户端后会在浏览器内生成对应格式并下载，不能提供可自动更新的 `/sub` 链接。
- 在线 IP 可用性检测在静态版不可用；优选 IP 来源 URL 需要来源站允许跨域。
- 下载的订阅文件包含 UUID，请勿公开分享。
- 需要自动更新订阅、在线检测和完整服务端转发时，继续使用 Vercel、Node.js 或 Docker 部署。

静态站点本身不含 UUID 或配置；它们只保存在当前浏览器和你的 Worker。免费账号的 GitHub Pages 需要公开仓库。

本地预览静态版：

```bash
npm ci
npm run build:pages
npx serve dist/pages
```

`npm run build:pages` 会把 `engine.mjs` 打包成浏览器模块，并在 `dist/pages/assets/` 下生成主题、静态面板脚本和已解压的分流规则。输出目录可用第一个参数指定，例如 `npm run build:pages -- /一个空目录`。

## Free CPU 保护

更新配套内核到 `2026.10.17.2`，在“配置管理”开启 **Free CPU 保护**，保存后对新连接生效。默认关闭，旧内核会提示更新。

开启后保留 WS 和 XHTTP：每条连接上下载合计最多 **384 KiB 或 96 个数据块**，超过就主动断开。新连接重新计算预算；关闭后恢复原来的传输方式。没有 KV 时可设置 Worker 变量 `freeCpu=yes` 或 `FREE_CPU=yes`，KV 中的设置优先。

这是按流量和处理次数估算的保护，Worker 无法读取实时 CPU 余量，不能保证所有免费账号零超限。客户端需自行重连，正在进行的下载、视频和长连接可能中断，不会自动续传。

## 自有服务器与 Docker

Node.js 22：

```bash
git clone https://github.com/byJoey/cfnew-panel.git
cd cfnew-panel
npm start
# 可选：固定自己的 Worker
w=https://your-worker.example.com npm start
```

运行不需要 npm 依赖，默认监听 `127.0.0.1:3100`。用 Nginx / Caddy 反代并启用 HTTPS。不要对外开放未加 HTTPS 的管理入口。

Docker：

```bash
docker compose up -d --build
# 固定 Worker 可在 .env 中填写 w，或通过环境变量传给 compose。
```

面板不把 UUID 或配置写入数据库。勾选“记住节点”只保存在当前浏览器；UUID 和订阅地址相当于访问凭据，勿公开分享，反代访问日志建议不记录这些入口。

## 更新与限制

- 一键部署得到自己的仓库副本。更新面板源码需同步上游并重新部署；修改环境变量也要重新部署。
- 原 WebSocket、XHTTP、出站代理、ECH、IPv6 与客户端订阅生成保留；代理数据面仍由配套核心处理。
- 在线 IP 检测在面板服务器执行，延迟是服务器视角。Vercel 实测 IPv4 检测可用，IPv6 在线检测出现平台出站错误；IPv6 节点生成和 Worker 实际连接已验证，不能用在线检测结果代替客户端测速。
- sing-box 使用 1.12 起的 DNS / 路由格式，内置分流规则，不要求启动时下载规则文件。规则许可见 [NOTICE](./NOTICE.md) 和 `/rules-license`。
- 请求正文上限 1 MiB，大量地址可改用在线列表 URL。健康检查为 `/health`。
- GitHub Pages 静态版只能托管静态页面：配置直连 Worker、订阅以文件下载，不能运行服务端订阅转发和在线检测；完整的自动更新订阅仍使用 Vercel Functions、Node.js 或 Docker。

## 开发与验证

```bash
npm ci
npm test
```

测试使用内存 KV 与本地隔离 Worker，不访问你的真实 Worker。`CFNEW_ALLOW_PRIVATE=yes` 仅供隔离测试，线上不要设置。

可生成单独的压缩运行包：

```bash
npm run build:vercel -- /一个空目录
```

规则更新：`python3 src/tools/update-singbox-rules.py --revision <完整提交号> --sing-box <可执行文件>`。更新后需验证真实客户端的 DNS、代理联网和分流，再发布。

## 来源与交流

允许任何合法用途的修改、二次开发和 AI 辅助维护。**禁止将基于本项目源码的 AI 改写冒充为与本项目无关的完全原创代码**；改写相同逻辑、换语言、改名或重排结构后，仍须保留来源和版权说明。可以注明自己实际新增的独立贡献。

本版本采用自定义的 [CFnew 源码使用与署名许可](./LICENSE)，不再标为标准 MIT。此前已按 MIT 发布的版本仍按其原许可使用。来源与第三方许可见 [NOTICE.md](./NOTICE.md)，内置规则数据继续遵循其原始许可。

[博客](https://joeyblog.net) · [YouTube](https://youtube.com/@joeyblog) · [Telegram](https://t.me/+ft-zI76oovgwNmRh)

本项目供学习与网络技术研究，请遵守当地法律及所用平台的服务条款。
