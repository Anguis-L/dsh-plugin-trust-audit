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

/** Hostnames a same-machine caller can legitimately use. */
const LOOPBACK_NAMES = new Set(['127.0.0.1', 'localhost', '[::1]', '::1'])

/** Default probe paths: the prefixes the installed community plugins use today. */
const DEFAULT_PATHS = [
  '/api/bili-duty/status',
  '/api/our-free-model/status',
]

const PROBE_TIMEOUT_MS = 4000

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
async function audit(ctx, { origin, paths }) {
  const target = resolveOrigin(ctx, origin)
  if (!target) {
    return {
      ok: false,
      reason: '拿不到可审计的回环地址：webServer 还没 listen，或传入的 origin 不是回环地址。请显式传入 origin，例如 http://127.0.0.1:61782',
      hint: '只审计回环地址 —— 对它机地址发起探测属于未授权扫描，本工具不做。',
    }
  }

  const list = Array.isArray(paths) && paths.length > 0 ? paths : DEFAULT_PATHS
  const findings = []

  for (const raw of list) {
    const path = String(raw)
    // Three probes per path, each answering a different question.
    const plain = await probe(`${target}${path}`, {})
    // A browser page on ANY localhost port can reach this if only the hostname
    // is compared — so a same-host-different-port Origin is the realistic
    // drive-by vector, not a non-loopback one.
    const crossPort = await probe(`${target}${path}`, { Origin: 'http://127.0.0.1:65535' })
    const crossSite = await probe(`${target}${path}`, { Origin: 'https://example.invalid' })

    const verdict = verdictFor(plain.status)
    findings.push({
      path,
      verdict,
      status: {
        unauthenticated: plain.status ?? null,
        crossPortOrigin: crossPort.status ?? null,
        crossSiteOrigin: crossSite.status ?? null,
      },
      risk: riskFor(verdict, path),
      note: plain.error ? `探测失败：${plain.error}` : undefined,
    })
  }

  const open = findings.filter(f => f.verdict === 'open')
  const unknown = findings.filter(f => f.verdict === 'unknown')

  return {
    ok: true,
    origin: target,
    probed: findings.length,
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
  // Register the audit tool. A hard dependency on `tools` keeps the plugin
  // from half-loading in a composition without a tool registry.
  ctx.inject(['tools'], scoped => {
    scoped.effect(() => scoped.tools.register({
      name: 'plugin_trust_audit',
      description:
        '只读审计：检查 DSH 端口上插件的 HTTP 路由是否真的做了鉴权栅栏。'
        + '对每个候选路径分别发「无凭据」「跨端口 Origin」「跨站 Origin」三组 GET 探测，'
        + '判定为 fenced(401/403) / open(200 无凭据) / absent(404) / unknown。\n'
        + '⚠️ 只探测回环地址；不发任何写请求；unknown 不等于安全。',
      parameters: {
        origin: {
          type: 'string',
          description: '要审计的回环地址，例如 http://127.0.0.1:61782。省略时自动取当前 webServer 的 origin。',
        },
        paths: {
          type: 'array',
          description: '要探测的路径列表。省略时探测已装社区插件的默认前缀。',
          items: { type: 'string' },
        },
      },
      output: textOutput,
      async execute(args) {
        const report = await audit(ctx, {
          origin: args?.origin,
          paths: args?.paths,
        })
        // The host rejects non-JSON values, so normalise before returning.
        try { return JSON.parse(JSON.stringify(report)) } catch { return { ok: false, reason: 'report not serialisable' } }
      },
    }), 'trust-audit: plugin_trust_audit tool')
  })

  // Deliberately no ctx.webServer.register(...) — see DESIGN CONSTRAINTS.
}
