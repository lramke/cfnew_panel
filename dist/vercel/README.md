# CFnew 独立面板部署包

兼容内核：2026.10.17.2。公开源码与一键部署：https://github.com/byJoey/cfnew-panel 。面板与订阅运行在 Vercel，代理核心和 KV 仍由你自己的 Cloudflare Worker 提供。

连接 Vercel 账号后部署本目录。部署成功后打开面板，填写 Worker 域名和 UUID 或自定义路径。

## 可选：只允许自己的 Worker

在 Vercel 项目的 Settings → Environment Variables 新增 w，例如 https://your-worker.example.com，然后重新部署。变量设置在面板项目，内核无需修改。

填写后只允许接入这个 Worker，直接访问 https://面板域名/UUID 或自定义路径进入原控制台，首页返回 hello，不显示连接表单；订阅使用 /UUID/sub，配置和优选接口同样受限。留空或不设置则为公共面板，任何人的 Worker 都能接入。HTTPS 前缀可以省略，不要带路径、查询参数或 UUID。填错会拒绝接入，不会自动放开。

UUID 或自定义路径仍然必填。变量只限制接入的 Worker，不代替 UUID 验证。环境变量按 Production / Preview 等环境分别设置，修改后要重新部署才生效。

订阅客户端需要直接访问面板。若 Vercel 要求登录，在 Settings → Deployment Protection 关闭 Vercel Authentication，或使用可公开访问的部署域名，否则客户端无法更新订阅。

此目录仅包含打包后的运行文件，不包含可维护源码、源码映射、测试数据或凭据。运行文件仍可以被分析；压缩并不是加密。

平台的登录、Git 授权和最终 Deploy 确认由平台要求，部署按钮无法替你跳过。IPv6 在线检测取决于部署平台的出站网络。

## 来源与许可

允许合法修改和二次开发；基于本项目的 AI 改写也须保留来源，禁止冒充原创。完整条款见随包 LICENSE，第三方说明见 NOTICE.md。此前按其他许可发布的版本继续适用其原许可。
