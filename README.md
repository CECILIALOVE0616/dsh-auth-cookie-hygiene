# dsh-auth-cookie-hygiene

> 给 DSH 本地认证 Cookie 做卫生的插件：在本地 HTTP 响应里追加过期 `Set-Cookie`，让浏览器自己删掉已经停止的 Host 留下的 `dsh-auth-*` Cookie。
>
> A DSH bundle plugin that expires stale loopback auth cookies, so a random-port desktop Host cannot pile them up until `Cookie` headers hit the HTTP 431 limit.

不修改安装包，不读写浏览器 Cookies 数据库，不碰签名密钥，不关闭认证，不调大请求头上限。

## 背景

DSH Desktop 每次启动会监听一个随机的 `127.0.0.1` 端口，并为该 Host 下发一个与之对应的 `dsh-auth-*` Cookie。浏览器不按端口隔离 Cookie，所以每个新端口都会多留一个 Cookie，旧端口的却永远不过期。用过一段时间后 `Cookie` 请求头会不断变长，最终在 HTTP parser 阶段被拒绝（`431 Request Header Fields Too Large`），表现为本地页面认证失败。

这个插件是**预防性缓解**，不是官方根治：

- 已经大到被 parser 拒绝的请求根本没进到应用层，插件看不到，必须先离线清一次 Cookie。
- 只有在判定旧端口确实没人监听时才清理，所以端口复原/进程切换的 TOCTOU 窗口无法彻底消除。
- 依赖当前版本的 `webServer.server` 接入点与 v1 Cookie 格式，不承诺跨大版本兼容。

## 清理与保留规则

只处理字面量 `127.0.0.1:端口` 的本地 HTTP 请求，且 `Host` 端口必须与实际监听端口一致。只有同时满足以下条件的 Cookie 才会被下发过期头：

1. 名字是 `dsh-auth-*`，格式自洽，且名字里的 authority 与其 SHA256 前缀相符（只做自洽性筛选，不代表验证真实签名）；
2. 该 authority 的端口两次新鲜探测均为 `ECONNREFUSED`，且两次间隔不小于 `confirmGapMs`；
3. 不是当前 Host，也不是任何正在监听的 Host。

始终保留：当前 Host、其他在监听 Host、v2/API Cookie、非 `127.0.0.1` 或 HTTPS 形态的 Cookie、畸形/超长/判定不确定的 Cookie。探测超时或其他错误一律按「未知」处理并保留。

过期头只在已认证的首页响应（显式 `200`/`303`、非流式）上合并发送；`401`/`403`、隐式发送、`write`/`flushHeaders` 流式响应会立刻原样放行。原有的 `Set-Cookie`、状态码、`Location` 和响应体都不变。

## 安装

插件是一个标准的 DSH bundle 包，零运行时依赖（只用 Node 内置模块，需要 Node ≥ 22.13）。

```bash
git clone https://github.com/CECILIALOVE0616/dsh-auth-cookie-hygiene.git
cd dsh-auth-cookie-hygiene
npm pack            # 产出 dsh-auth-cookie-hygiene-<version>.tgz
```

然后在 DSH 的 profile 目录（与 `cordis.patch.yml` 同级）里：

1. 安装依赖：`npm install <tgz 路径>`
2. 把同名 bundle 加进 profile 配置的 `dsh.profile.bundles`
3. 包内 `dsh.bundle.patch` 指向 `cordis.patch.yml`，由它把 backend 插件插进配置树：

```yaml
- insert:
    - id: dsh-auth-cookie-hygiene
      name: dsh-auth-cookie-hygiene
```

4. 重启 DSH，先走一遍 welcome / account 流程确认登录正常。

安装前备份 profile 并退出 DSH；不要在运行中的 profile 上并发改依赖。卸载时移除 bundle 与依赖再重启，`effect` 会释放挂钩。

## 配置

全部可选，非法值回落默认值。写在与上面同一个 `insert` 条目的 `config` 下即可。

| 键 | 默认 | 范围 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `true` | — | 关掉后只挂载不清理 |
| `maxPerResponse` | `8` | 1–32 | 单次响应最多下发多少个过期头 |
| `maxExtraHeaderBytes` | `3072` | 256–16384 | 单次响应追加头的字节上限 |
| `maxCandidatesPerRequest` | `64` | 1–256 | 单次请求最多解析多少个候选 Cookie |
| `confirmTimeoutMs` | `700` | 100–5000 | 等待新鲜探测的总预算；到点放行 |
| `probeTimeoutMs` | `250` | 20–5000 | 单次 TCP 探测超时 |
| `confirmGapMs` | `120` | 0–60000 | 两次拒绝探测之间的最小间隔 |
| `closedTtlMs` | `30000` | 100–600000 | 「已关闭」缓存时长 |
| `openTtlMs` | `15000` | 100–600000 | 「在监听」缓存时长 |
| `retryBackoffMs` | `2000` | 50–60000 | 探测失联后的重试退避 |
| `maxPorts` | `256` | 1–4096 | 端口状态表上限 |
| `maxRecent` | `512` | 16–4096 | 近期已处理 Cookie 记录上限 |
| `recentTtlMs` | `300000` | 0–3600000 | 近期记录保留时长 |
| `serverPollMs` | `50` | 10–5000 | 未接入时的轮询间隔 |
| `serverIdlePollMs` | `2000` | 10–60000 | 已接入后的轮询间隔 |
| `serverDeadlineMs` | `30000` | 0–300000 | 等待 WebServer 出现的最长时间，0 表示不限 |
| `debug` | `false` | — | 输出接入与配置日志 |

不建议放大限额或等待时间：真正的约束是浏览器端的请求头总大小，不是这里。

## 开发与测试

```bash
npm test               # node --test "test/*.test.js"
npm run test:sandboxed # 受限环境下关掉测试进程隔离（Node 24+ 支持）
```

共 50 项测试，覆盖冷请求、活跃 Host 保留、v2/畸形输入、原登录头合并、401 不变、流式响应、探测超时与卸载放行，以及「无预热、无人工等待，连续 12 次重建 Host 后浏览器 Cookie jar 依然只有当前与另一个活跃 Host」。用 Electron 内置 Node 24.21.0 与 Node 24.22.1 均通过。

如果测试环境不允许 `node --test` 派生子进程（某些沙箱里会 `spawn EPERM`），改用 `npm run test:sandboxed`，它把 runner 的进程隔离关掉，在单个进程里跑同一个 glob。

模块职责：

| 文件 | 职责 |
| --- | --- |
| `lib/cookie.js` | Cookie 解析、authority/name 校验、过期头构造 |
| `lib/liveness.js` | 仅 127.0.0.1 的 TCP 探测与两次拒绝确认 |
| `lib/hook.js` | 请求/响应门控，只在认证首页响应上合并过期头 |
| `lib/index.js` | Cordis 生命周期、`webServer.server` 接入、配置归一化 |

## 已知限制

- 不修复已经触发的 431，只做预防。堆积较多时先退出 DSH 离线清理一次。
- 插件不读取 credentials 里的签名密钥，因此无法验证 Cookie 真实性，只做格式自洽 + 端口关闭筛选。
- 端口在探测与删除之间重新启用时可能误过期一个刚启用的实例，需要重新打开登录链接。
- 单次响应默认最多 8 条过期头，意味着首屏可能清不完大量历史 Cookie，多刷新几次即可。
- 真实桌面 profile 的 Electron welcome/account 全流程、Chromium 持久 Cookie 库的长期表现、DSH 升级后的兼容性，均未做完整验收。

## 许可

MIT