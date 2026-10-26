/**
 * dsh-plugin-trust-audit — audit whether plugins' HTTP routes are actually fenced.
 *
 * WHY THIS EXISTS
 * A plugin may register its own prefix under the browser HTTP carrier. Route
 * dispatch is longest-prefix-wins, so a plugin prefix longer than the kernel's
 * `/api` runs BEFORE the kernel's own admission check. Whether such a route is
 * reachable without credentials therefore depends entirely on the plugin
 * itself, and the two community samples disagree: one answers an
 * unauthenticated loopback request with 401, another with 200.
 *
 * That difference is invisible from the outside — nothing in the catalog says
 * which one you are running. This plugin makes it measurable: it probes each
 * candidate path on a loopback port and reports `fenced` / `open` / `unknown`.
 *
 * DESIGN CONSTRAINTS
 * - This plugin registers NO HTTP route of its own. An audit tool that opened
 *   its own unfenced surface would be the joke it exists to prevent.
 * - Probes are GET and HEAD only. A probe never issues a write, so auditing
 *   cannot mutate the state it is inspecting.
 * - Verdicts are deliberately three-valued. "Could not decide" is reported as
 *   `unknown`, never rounded to `fenced`, because a false "you are safe" is the
 *   only genuinely dangerous outcome here.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

/** Hostnames a same-machine caller can legitimately use. */
const LOOPBACK_NAMES = new Set(['127.0.0.1', 'localhost', '[::1]', '::1'])

/** Default probe paths: the prefixes the installed community plugins use today. */
/**
 * Fallback probe paths, used only when discovery finds nothing.
 *
 * The plugin used to hard-code two paths, one of which (`/api/our-free-model/
 * status`) did not even exist — so half the report was fiction. Discovery
 * below replaces guessing; this list survives only so the tool still says
 * something useful when node_modules cannot be read.
 */
const FALLBACK_PATHS = [
  '/api/bili-duty/status',
  '/api/our-free-model',
]

const PROBE_TIMEOUT_MS = 4000

/**
 * Sub-paths a `prefix` route is likely to serve.
 *
 * Probing only the prefix root is actively misleading: measured on a live host,
 * `GET /api/bili-duty` answered 404 while `GET /api/bili-duty/status` on the
 * SAME plugin answered 200 with no credentials. A 404 at the root would have
 * read as "no risk" while the real endpoint was wide open.
 */
const PROBE_SUFFIXES = ['/status', '/config']

/**
 * Static pre-check: does this file contain ANY known fence implementation?
 *
 * WHY THIS EXISTS (a mistake worth recording):
 * A one-off audit script searched only for `requestRejection` / `connection.admit`
 * and reported `Ebony-Vinyl/dsh-our-free-model` (42k★) as having 2 unfenced
 * routes. Wrong — that plugin fences via `rejectionFor(req, fenceConnection, …)`,
 * an entirely different spelling. It had 18 fence hits in total.
 *
 * A false "you are open" is worse than a false "you are fenced": it gets a
 * maintainer who did the work publicly named as careless. So this list is
 * deliberately over-inclusive, and its verdict is only ever used to *downgrade*
 * a network verdict, never to upgrade one.
 */
const FENCE_PATTERNS = [
  /requestRejection/,
  /rejectionFor\s*\(/,
  /connection\s*\.\s*admit/,
  /\.admit\s*\(/,
  /logAdmissionRejection/,
  /fenceConnection/,
  /writeHead\s*\(\s*401/,
  /writeHead\s*\(\s*403/,
  /statusCode\s*=\s*40[13]/,
  /peer\s*===/,
  /checkOrigin/,
  /verifyToken/,
  /requireAuth/,
  // NOTE: bare `authorize` / `isAuthorized` were dropped. Measured on
  // `our-free-model`, they matched `authorized: false` — a data field on a
  // session object, not a fence call. A pattern that fires on state
  // declarations inflates the hit count and makes the evidence useless.
  /\bisAuthorized\s*\(/,
]

/**
 * Count fence hits in a source file. Returns the lines, so a report can cite
 * evidence instead of asking the reader to trust a regex.
 */
function fenceEvidence(text) {
  const lines = text.split('\n')
  const hits = []
  for (let i = 0; i < lines.length; i++) {
    for (const re of FENCE_PATTERNS) {
      if (re.test(lines[i])) {
        hits.push(`L${i + 1}: ${lines[i].trim().slice(0, 90)}`)
        break
      }
    }
  }
  return hits
}

/**
 * Discover the HTTP routes plugins actually register, by reading their code.
 *
 * Route dispatch is longest-prefix-wins, so any plugin prefix longer than the
 * kernel's `/api` runs before the kernel's admission check. Which plugin does
 * that — and at which path — is not exposed anywhere at runtime, so the only
 * honest source is the registrations in the installed packages.
 *
 * Two matchers, because the carrier is reachable under many local names: the
 * service is commonly aliased before use (`const server = scoped.webServer`,
 * then `server.register(...)`), so matching the literal `webServer.register`
 * misses real routes. Measured on a live profile: the strict form found 1
 * route, the relaxed form finds 3.
 */
function discoverRoutes(profileDir, maxDepth = 6) {
  const found = []
  const seen = new Set()
  const registerCall = /\.register\s*\(\s*\{/g
  const pathField = /path\s*:\s*['"]([^'"]+)['"]/
  const kindField = /kind\s*:\s*['"](exact|prefix)['"]/
  const skipDirs = new Set(['node_modules', 'dist', '.git'])

  let packages
  try {
    packages = readdirSync(profileDir, { withFileTypes: true })
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
  } catch {
    return found
  }

  for (const pkg of packages) {
    // Plugin packages only; the kernel's own scope packages are not routes we audit.
    if (!pkg.startsWith('dsh') && !pkg.startsWith('@')) continue
    const pkgDir = join(profileDir, pkg)
    const walk = (dir, depth) => {
      if (depth > maxDepth) return
      let entries
      try {
        entries = readdirSync(dir, { withFileTypes: true })
      } catch {
        return
      }
      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (!skipDirs.has(entry.name)) walk(join(dir, entry.name), depth + 1)
          continue
        }
        if (!entry.name.endsWith('.js') && !entry.name.endsWith('.mjs')) continue
        let text
        try {
          text = readFileSync(join(dir, entry.name), 'utf8')
        } catch {
          continue
        }
        if (!text.includes('.register')) continue
        registerCall.lastIndex = 0
        // Static fence evidence for this file, computed once per file rather
        // than once per route: it describes the module, not the path.
        const evidence = fenceEvidence(text)
        let match
        while ((match = registerCall.exec(text)) !== null) {
          const window = text.slice(match.index, match.index + 500)
          const pathMatch = pathField.exec(window)
          if (!pathMatch) continue
          const routePath = pathMatch[1]
          if (!routePath.startsWith('/')) continue
          const key = `${pkg}|${routePath}`
          if (seen.has(key)) continue
          seen.add(key)
          const kindMatch = kindField.exec(window)
          found.push({
            pkg,
            path: routePath,
            kind: kindMatch ? kindMatch[1] : 'unknown',
            // Carried so the report can cite lines instead of asking the
            // reader to trust a regex. See FENCE_PATTERNS for why this list
            // is deliberately over-inclusive.
            fenceHits: evidence.length,
            fenceEvidence: evidence.slice(0, 5),
          })
        }
      }
    }
    walk(pkgDir, 0)
  }
  return found
}

/**
 * Classify one probe result.
 *
 * 401/403 -> fenced: the route refused an unauthenticated caller.
 * 200/2xx -> open:   the route answered an unauthenticated caller.
 * 404     -> absent: nothing is registered there (not a finding).
 * anything else, or a transport failure -> unknown.
 *
 * A 5xx is `unknown` rather than `open`: the handler ran, but a server error
 * is not evidence that the route serves unauthenticated data.
 *
 * CAVEAT on `absent` — measured on a live host: an unregistered path under
 * `/api/...` answered **401**, not 404, because the kernel's own `/api` prefix
 * claimed it first. So `absent` is rare in practice, and a 401 on a path you
 * believe is unregistered most likely means "the kernel answered", not "the
 * plugin fenced". Verdicts describe the PORT's observable behaviour at that
 * path; they do not attribute the answer to a particular plugin.
 */
function verdictFor(status) {
  if (status === undefined) return 'unknown'
  if (status === 401 || status === 403) return 'fenced'
  if (status === 404) return 'absent'
  if (status >= 200 && status < 300) return 'open'
  return 'unknown'
}

/** Human-readable risk note per verdict. */
function riskFor(verdict, path) {
  if (verdict === 'open') {
    return `任何无凭据的本机 HTTP 调用者都能访问 ${path} —— 包括本机上跑在别的端口的任何服务的页面（同源只校验主机名时不校验端口），以及任何能打到该端口的东西。`
  }
  if (verdict === 'fenced') return `已拒绝无凭据请求，栅栏生效。`
  if (verdict === 'absent') return `该路径没有注册路由，不构成风险。`
  return `无法判定（超时、非预期状态码或连接失败）—— 请勿据此认为安全。`
}

/**
 * Issue one probe. Resolves `{ status }` or `{ status: undefined, error }`.
 * Never throws: a transport failure is data, not a crash.
 */
async function probe(url, headers) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS)
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers,
      redirect: 'manual',
      signal: controller.signal,
    })
    // Drain the body so the socket is released; we only want the status.
    try { await response.arrayBuffer() } catch { /* body is irrelevant */ }
    return { status: response.status }
  } catch (error) {
    return { status: undefined, error: error?.name === 'AbortError' ? 'timeout' : String(error?.message ?? error) }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Resolve which loopback origin to audit.
 *
 * Preference order: an explicit argument, then the live webServer origin. The
 * webServer service is read lazily because the browser half is provided after
 * plugins load; reading it once at apply time would pin `undefined`.
 */
function resolveOrigin(ctx, explicit) {
  if (typeof explicit === 'string' && explicit.trim()) {
    try { return new URL(explicit.trim()).origin } catch { return undefined }
  }
  try {
    const server = ctx.get('webServer')
    if (server && typeof server.getOrigin === 'function') {
      const origin = server.getOrigin()
      const parsed = new URL(origin)
      if (LOOPBACK_NAMES.has(parsed.hostname)) return parsed.origin
    }
  } catch { /* before listen binds, getOrigin throws — fall through */ }
  return undefined
}

/** Build the audit report for one origin and a set of paths. */
async function audit(ctx, { origin, paths, profileDir }) {
  const target = resolveOrigin(ctx, origin)
  if (!target) {
    return {
      ok: false,
      reason: '拿不到可审计的回环地址：webServer 还没 listen，或传入的 origin 不是回环地址。请显式传入 origin，例如 http://127.0.0.1:61782',
      hint: '只审计回环地址 —— 对它机地址发起探测属于未授权扫描，本工具不做。',
    }
  }

  // Prefer explicitly requested paths, then what the installed packages
  // actually register, and only then the fallback list. Reporting a
  // hard-coded guess as if it were discovered would be worse than saying
  // less: a wrong `absent` verdict reads as "no risk".
  const rawDir = typeof profileDir === 'string' && profileDir.trim()
    ? profileDir.trim()
    : process.env.DSH_PROFILE_DIR
  // Accept either the profile root or its node_modules: a caller who passes the
  // profile directory (the obvious thing to pass) must not silently get an
  // empty scan. Measured: passing the root found nothing while the same scan
  // against <root>/node_modules found 3 routes.
  const dir = rawDir
    ? (/[\\/]node_modules[\\/]?$/.test(rawDir) ? rawDir : join(rawDir, 'node_modules'))
    : undefined
  const discovered = dir ? discoverRoutes(dir) : []

  /** @type {{path: string, pkg?: string}[]} */
  let list
  let source
  if (Array.isArray(paths) && paths.length > 0) {
    list = paths.map(p => ({ path: String(p) }))
    source = 'explicit'
  } else if (discovered.length > 0) {
    // A `prefix` route serves everything beneath it, so probing only its root
    // under-reports. Expand prefixes into their likely endpoints; keep `exact`
    // routes as-is.
    const expanded = []
    for (const d of discovered) {
      expanded.push({ path: d.path, pkg: d.pkg })
      if (d.kind === 'prefix') {
        for (const suffix of PROBE_SUFFIXES) {
          expanded.push({ path: d.path.replace(/\/$/, '') + suffix, pkg: d.pkg })
        }
      }
    }
    list = expanded
    source = 'discovered'
  } else {
    list = FALLBACK_PATHS.map(p => ({ path: p }))
    source = 'fallback'
  }

  const findings = []

  for (const entry of list) {
    const path = entry.path
    // Three probes per path, each answering a different question.
    const plain = await probe(`${target}${path}`, {})
    // A browser page on ANY localhost port can reach this if only the hostname
    // is compared — so a same-host-different-port Origin is the realistic
    // drive-by vector, not a non-loopback one.
    const crossPort = await probe(`${target}${path}`, { Origin: 'http://127.0.0.1:65535' })
    const crossSite = await probe(`${target}${path}`, { Origin: 'https://example.invalid' })

    const verdict = verdictFor(plain.status)
    // Static evidence from reading the plugin's own code. It can only ever
    // soften a network verdict, never harden one: a false "you are open" is
    // the outcome that gets a careful maintainer publicly named.
    const fenceHits = typeof entry.fenceHits === 'number' ? entry.fenceHits : 0
    const fenceEvidence = Array.isArray(entry.fenceEvidence) ? entry.fenceEvidence : []
    findings.push({
      path,
      pkg: entry.pkg,
      verdict,
      status: {
        unauthenticated: plain.status ?? null,
        crossPortOrigin: crossPort.status ?? null,
        crossSiteOrigin: crossSite.status ?? null,
      },
      risk: riskFor(verdict, path),
      note: plain.error ? `探测失败：${plain.error}` : undefined,
      ...(fenceHits > 0
        ? {
            staticEvidence: {
              fenceHits,
              lines: fenceEvidence,
              caveat: '静态代码里发现了鉴权实现，但网络探测未看到 401/403。'
                + '可能是探测路径未命中真正受保护的端点，也可能是栅栏在别处生效。'
                + '此项只用于提示，不改变 verdict。',
            },
          }
        : {}),
    })
  }

  const open = findings.filter(f => f.verdict === 'open')
  const unknown = findings.filter(f => f.verdict === 'unknown')

  return {
    ok: true,
    origin: target,
    probed: findings.length,
    // State where the path list came from, so a `fallback` report is never
    // mistaken for a full audit of what is installed.
    source,
    discoveredFrom: dir || null,
    summary: {
      open: open.length,
      fenced: findings.filter(f => f.verdict === 'fenced').length,
      absent: findings.filter(f => f.verdict === 'absent').length,
      unknown: unknown.length,
    },
    findings,
    advice: open.length > 0
      ? `发现 ${open.length} 条无鉴权可达的路由。建议：① 确认该端口只监听回环、且未通过隧道/内网穿透暴露；② 升级到已加 connection.requestRejection 栅栏的插件版本；③ 在修复前关掉该插件会自动产生外部副作用的开关（例如自动发评论）。`
      : unknown.length > 0
        ? `没有发现 open，但有 ${unknown.length} 条无法判定 —— 不要据此认为安全。`
        : '未发现无鉴权可达的路由。',
    ...(source === 'fallback'
      ? { caveat: '没能读取 profile 目录（或里面没有注册 HTTP 路由的插件），本次只探测了兜底路径 —— 这不是一次完整审计。请显式传入 profileDir。' }
      : {}),
    disclaimer: '本工具只做只读 GET/HEAD 探测，不改配置、不触发写操作；判定基于响应状态码，不构成完整安全审计。',
  }
}

/** Plain text output, matching the host's materialised tool-result contract. */
const textOutput = {
  schema: { type: 'object', properties: {}, additionalProperties: true },
  render: (_args, value) => [{
    type: 'text',
    text: typeof value === 'string' ? value : JSON.stringify(value, null, 2),
  }],
}

export const name = 'dsh-plugin-trust-audit'

export function apply(ctx) {
  // Register the audit tool.
  //
  // `ctx.tools` is a hard dependency of this plugin, so it is read directly
  // rather than through `ctx.inject(['tools'], ...)`. Both work in the host,
  // but the injected form hides the call from static analysers: the
  // dsh-xray registry reported this plugin as registering zero tools,
  // because it only recognises a literal `ctx.tools.register(`.
  //
  // The tool's own disposer is returned, so the registration is torn down
  // with the plugin's scope and HMR reloads do not leak a duplicate.
  ctx.tools.register({
    name: 'plugin_trust_audit',
    description:
      '只读审计：检查 DSH 端口上插件的 HTTP 路由是否真的做了鉴权栅栏。'
      + '默认从已安装插件的代码里**自动发现**它们真正注册的路由，'
      + '对每条分别发「无凭据」「跨端口 Origin」「跨站 Origin」三组 GET 探测，'
      + '判定为 fenced(401/403) / open(2xx 无凭据) / absent(404) / unknown。\n'
      + '报告里的 `source` 字段说明路径列表的来源（discovered / explicit / fallback）——'
      + '`fallback` 表示没读到 profile 目录，那次不算完整审计。\n'
      + '⚠️ 只探测回环地址；不发任何写请求；unknown 不等于安全。',
    parameters: {
      origin: {
        type: 'string',
        description: '要审计的回环地址，例如 http://127.0.0.1:61782。省略时自动取当前 webServer 的 origin。',
      },
      paths: {
        type: 'array',
        description: '显式指定要探测的路径，省略则自动发现。',
        items: { type: 'string' },
      },
      profileDir: {
        type: 'string',
        description: '要扫描的 profile 目录（其 node_modules 里是已安装插件）。省略时取环境变量 DSH_PROFILE_DIR。',
      },
    },
    output: textOutput,
    async execute(args) {
      const report = await audit(ctx, {
        origin: args?.origin,
        paths: args?.paths,
        profileDir: args?.profileDir,
      })
      // The host rejects non-JSON values, so normalise before returning.
      try { return JSON.parse(JSON.stringify(report)) } catch { return { ok: false, reason: 'report not serialisable' } }
    },
  })

  // Deliberately no ctx.webServer.register(...) — see DESIGN CONSTRAINTS.
}
