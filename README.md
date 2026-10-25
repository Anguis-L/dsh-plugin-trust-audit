# dsh-plugin-trust-audit

只读审计：**DSH 端口上插件的 HTTP 路由，是否真的做了鉴权栅栏。**

[![DSH 1024Store](https://img.shields.io/badge/1024Store-catalogued-blue)](https://deepseek1024.com/)

## 安装

```bash
# 方式一：从 GitHub Release 直链安装（不需要 npm 账号，不需要 git）
dsh plugin --profile <你的profile> add \
  https://github.com/Anguis-L/dsh-plugin-trust-audit/releases/download/v0.3.0/dsh-plugin-trust-audit-0.3.0.tgz

# 方式二：从 GitHub 仓库安装
dsh plugin --profile <你的profile> add github:Anguis-L/dsh-plugin-trust-audit
```

当前版本 **v0.3.0**。装完**重启一次** dsh（bundle 层要重启才组装），
然后在会话里直接让 agent 调用 `plugin_trust_audit`。

## 为什么需要它

插件可以在浏览器 HTTP 载体上注册自己的前缀，而路由分发是**最长前缀优先**。一个比内核 `/api` 更长的插件前缀，会**先于**内核自己的准入检查执行 —— 于是"这条路由是否需要凭据"完全取决于插件自己，而社区里的两个样本结论相反：

| 实现 | 无凭据回环请求 |
|---|---|
| `dsh-our-free-model`（用 `connection.requestRejection`） | **401** 已拦 |
| `dsh-bili-scroll` 2.0.4（只有结构化栅栏） | **200** 放行 |

这个差别从外面看不出来 —— 插件目录里没有任何字段告诉你装的是哪一种。本插件把它变成可测量的。

## 判定口径

对每个候选路径发三组**只读 GET** 探测，每组回答不同的问题：

| 探测 | 头 | 回答什么 |
|---|---|---|
| 无凭据 | 无 | 裸奔的调用者能不能拿到数据 |
| 跨端口 Origin | `Origin: http://127.0.0.1:65535` | 本机**别的端口**上的页面能不能驱动它（只比主机名、不比端口时会放行） |
| 跨站 Origin | `Origin: https://example.invalid` | 外部网页能不能驱动它 |

判定：

| 状态码 | 判定 | 含义 |
|---|---|---|
| 401 / 403 | `fenced` | 栅栏生效 |
| 2xx | `open` | **无鉴权可达** |
| 404 | `absent` | 没注册路由，不构成风险 |
| 其它 / 超时 / 连不上 | `unknown` | **不等于安全** |

`unknown` 是三值判定的关键：把"判不了"糊成"安全"，是这里唯一真正危险的结果。

### ⚠️ 关于 `absent` 的一个实测坑

在真实宿主上测过：一条**没被任何插件注册**的路径，比如 `/api/nonexistent-xyz`，返回的是 **401 而不是 404** —— 因为内核自己的 `/api` 前缀先接住了它。

所以：`absent` 在实践中很少出现；**一条你以为"没注册"却返回 401 的路径，大概率是内核答的，不是插件栅栏生效**。

因此判定描述的是**该端口在该路径上的可观测行为**，它**不**把响应归属到某个具体插件。要判断"这是不是插件栅栏"，需要结合该插件源码里是否真的做了 `connection.requestRejection`。

## 它自己不开任何 HTTP 路由

一个审计工具如果自己开了个裸奔的接口，就是它存在的意义本身的笑话。所以本插件**只注册一个 Host 工具，没有 `webServer.register`**。

## 自动发现路由（0.2.0 起）

0.1.x 里探的是两条**硬编码**路径，其中一条（`/api/our-free-model/status`）根本不存在 —— **一半的报告是编的**。

0.2.0 改成从已安装插件的代码里**读出它们真正注册的路由**：

- 匹配 `<任何别名>.register({ kind, path, handler })` —— 不能只匹配 `webServer.register`，因为实际代码普遍先起别名（`const server = scoped.webServer` 再 `server.register(...)`）。实测：严格匹配只找到 1 条，放宽后找到 3 条。
- 遇到 `kind: 'prefix'` 会**连带探测子路径**（`/status`、`/config`）。这一步不是锦上添花：实测 `/api/bili-duty` 返回 **404**，而同一插件的 `/api/bili-duty/status` 返回 **200 无凭据** —— 只探前缀根会把一个敞开的接口报成"无风险"。
- 报告里的 `source` 字段说明路径来源：`discovered` / `explicit` / `fallback`。**`fallback` 表示没读到 profile 目录，那次不算完整审计**，会额外带一条 `caveat`。

实测一次输出（本机装了 2 个插件）：

```
source=discovered  probed=7  summary={"open":2,"fenced":4,"absent":1,"unknown":0}

  absent   404  dsh-bili-scroll      /api/bili-duty
  open     200  dsh-bili-scroll      /api/bili-duty/status
  open     200  dsh-bili-scroll      /api/bili-duty/config
  fenced   401  dsh-our-free-model   /api/our-free-model
  fenced   401  dsh-our-free-model   /api/our-free-model/status
  fenced   401  dsh-our-free-model   /api/our-free-model/config
  fenced   401  dsh-our-free-model   /api/our-free-model/events
```

同一个端口上，两个插件一个 `open` 一个 `fenced` —— **这就是本工具存在的理由**。

## 0.3.0：加静态预检，修掉一个假阳性

0.2.0 只靠**网络探测**判定。后来我用另一个一次性脚本读代码，只搜了 `requestRejection` / `connection.admit`，
就把 `Ebony-Vinyl/dsh-our-free-model`（42k★）报成「2 条路由无鉴权」—— **错的**。
它用的是 `rejectionFor(req, fenceConnection, …)`，另一种写法，实际有 **18 处**鉴权代码。

假阳性比漏报危险：它会把一个做了防护的维护者公开点名成"不在意安全"。

所以 0.3.0 在每条路由上附带**静态证据**：

```
staticEvidence: {
  fenceHits: 6,
  lines: [
    "L1020: const fenceConnection = connectionAdmissionView(() => optional('connection'))",
    "L1063: const logAdmissionRejection = surface => ({ status, source, reason }) => {",
    "L1369: connection: fenceConnection,",
    "L1370: onAdmissionRejection: logAdmissionRejection('settings API'),"
  ],
  caveat: '静态代码里发现了鉴权实现，但网络探测未看到 401/403。…'
}
```

两条设计规则：

1. **白名单宁宽勿窄**。漏报只是少报一个，误报会伤害无辜的维护者。
2. **静态证据只能软化判定，不能硬化**。网络探测看到 `open` 而代码里有栅栏时，`verdict` 不变，
   只是多带一条 `staticEvidence` 提示——因为探测路径可能没命中真正受保护的端点。

顺带收紧了一个模式：0.3.0 之前 `authorize` / `isAuthorized` 会匹配到
`authorized: false` 这种**会话对象的数据字段**，把命中数从 6 虚涨到 15，证据反而没法看。
现在只认 `isAuthorized(` 这种真正的调用形态。

## 只读

只发 `GET`，**从不发写请求**，所以审计不会改变它正在检查的状态。

## 用法

```
plugin_trust_audit()                                                  # 自动发现 + 探测
plugin_trust_audit({ origin: 'http://127.0.0.1:61782' })
plugin_trust_audit({ profileDir: 'C:/Users/you/.dsh/profiles/desktop' })  # 指定要扫哪个 profile
plugin_trust_audit({ paths: ['/api/my-plugin/config'] })                  # 只探指定路径
```

只审计回环地址。对**它机**地址发起探测属于未授权扫描，本工具不做。

## 局限

判定基于响应状态码，不构成完整安全审计：它不能证明一条返回 401 的路由内部没有别的洞，也不能发现只在特定方法/参数下才触发的问题。

自动发现是**读代码猜路径**，不是运行时注册表查询（宿主没把这个信息暴露出来）。所以：

- 路径写得很动态的插件（`path: '/api/' + name`）可能扫不到；
- 子路径只探 `/status`、`/config` 两个常见名，其他端点需要显式传 `paths`；
- 扫不到时报告会明确写 `source: fallback` + `caveat`，**不会假装是一次完整审计**。

---

## 关于

如果这个工具帮你发现了什么问题，那就是它存在的意义。

如果你愿意请我喝杯咖啡，可以扫这个码 —— **完全自愿，不给也照样能看能用**：

<img src="alipay-qr.png" alt="支付宝收款码" width="200">

相关：[DSH 插件真实下载榜](https://anguis-l.github.io/dsh-ranking/) —— 用 npm 真实下载量给插件排名
