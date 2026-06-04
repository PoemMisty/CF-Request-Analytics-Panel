const CONFIG_KEY = "accounts:v1";
const PRIVACY_KEY = "privacy:v1";
const SESSION_TTL = 60 * 60 * 24;
const RANGE_HOURS = new Set([1, 6, 12, 24]);
const GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";
const DEFAULT_AI_MODEL = "@cf/openai/gpt-oss-20b";
const DAILY_REQUEST_LIMIT = 100000;
const NO_ACCOUNT_MESSAGE = "当前还没有账号配置。请先登录后台添加 Cloudflare 账号后再查看分析或使用 AI 分析。";

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (!env.ADMIN_PASSWORD) return setupRequiredPage();
      const missingBindings = getMissingBindings(env);
      if (missingBindings.length) return setupRequiredPage(missingBindings);
      if (url.pathname === "/") return html(INDEX_HTML);
      if (url.pathname === "/login") return html(LOGIN_HTML);
      if (url.pathname === "/admin") {
        if (!(await isAdmin(request, env))) return redirect("/login");
        return html(ADMIN_PANEL_HTML);
      }
      if (url.pathname === "/api/session") return sessionRoute(request, env);
      if (url.pathname === "/api/login" && request.method === "POST") return login(request, env);
      if (url.pathname === "/api/logout" && request.method === "POST") return logout();
      if (url.pathname === "/api/accounts") return accountsRoute(request, env);
      if (url.pathname === "/api/privacy") return privacyRoute(request, env);
      if (url.pathname === "/usage.json" || url.pathname === "/api/usage") return usageRoute(request, env);
      if (url.pathname === "/api/analytics") return analyticsRoute(request, env);
      if (url.pathname === "/api/ai/analyze" && request.method === "POST") return aiRoute(request, env);
      if (url.pathname === "/robots.txt") return text("User-agent: *\nDisallow: /\n");
      return json({ error: "not_found" }, 404);
    } catch (error) {
      return json({ error: "internal_error", message: safeErrorMessage(error) }, 500);
    }
  },
};

function safeErrorMessage(error) {
  if (!error) return "未知错误";
  if (typeof error === "string") return error;
  if (typeof error.message === "string" && error.message) return error.message;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

async function sessionRoute(request, env) {
  const admin = await isAdmin(request, env);
  return json({ admin, aiAvailable: hasAiBinding(env), privacy: await readPrivacy(env) });
}

function hasAiBinding(env) {
  return Boolean(env.AI && typeof env.AI.run === "function");
}

async function login(request, env) {
  const body = await request.json().catch(() => ({}));
  const expectedUser = env.ADMIN_USER || "admin";
  const expectedPassword = env.ADMIN_PASSWORD;
  if (!expectedPassword) return json({ error: "missing_ADMIN_PASSWORD" }, 500);
  if (body.username !== expectedUser || body.password !== expectedPassword) {
    return json({ error: "invalid_credentials" }, 401);
  }
  const token = await signSession(request, env);
  return json({ ok: true }, 200, {
    "Set-Cookie": `cfra_session=${token}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; SameSite=Lax; Secure`,
  });
}

function logout() {
  return json({ ok: true }, 200, {
    "Set-Cookie": "cfra_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure",
  });
}

async function accountsRoute(request, env) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  if (request.method === "GET") {
    const accounts = await readAccounts(env);
    const usableAccounts = await Promise.all(accounts.map((account) => decryptAccount(account, env)));
    return json({ accounts: usableAccounts.map(publicAccount) });
  }
  if (request.method === "POST") {
    const input = await request.json().catch(() => ({}));
    const accounts = await readAccounts(env);
    await validateAccountConfig(input, env);
    const result = await upsertAccount(accounts, input, env);
    await writeAccounts(env, result.accounts);
    return json({ account: publicAccount(result.account), action: result.action, addedZones: result.addedZones, mergedDuplicates: result.mergedDuplicates || 0 });
  }
  if (request.method === "PUT") {
    const input = await request.json().catch(() => ({}));
    const accounts = await readAccounts(env);
    const result = await updateAccountLabels(accounts, input, env);
    await writeAccounts(env, result.accounts);
    return json({ account: publicAccount(result.account) });
  }
  if (request.method === "PATCH") {
    const input = await request.json().catch(() => ({}));
    const accounts = await readAccounts(env);
    const result = await addAccountZones(accounts, input, env);
    await writeAccounts(env, result.accounts);
    return json({ account: publicAccount(result.account), addedZones: result.addedZones });
  }
  if (request.method === "DELETE") {
    const url = new URL(request.url);
    const id = url.searchParams.get("id");
    const zoneId = url.searchParams.get("zoneId");
    const accounts = await readAccounts(env);
    if (zoneId) {
      const result = await removeAccountZone(accounts, id, zoneId, env);
      await writeAccounts(env, result.accounts);
      return json({ account: publicAccount(result.account) });
    }
    await writeAccounts(env, accounts.filter((item) => item.id !== id));
    return json({ ok: true });
  }
  return json({ error: "method_not_allowed" }, 405);
}

async function privacyRoute(request, env) {
  const admin = await isAdmin(request, env);
  if (request.method === "GET") return json({ privacy: await readPrivacy(env) });
  if (!admin) return json({ error: "unauthorized" }, 401);
  if (request.method === "PUT") {
    const input = await request.json().catch(() => ({}));
    const privacy = normalizePrivacy(input);
    await writePrivacy(env, privacy);
    return json({ privacy });
  }
  return json({ error: "method_not_allowed" }, 405);
}

async function usageRoute(request, env) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: usageCorsHeaders() });
  const accounts = await readAccounts(env);
  if (!accounts.length) return json(usageApiPayload(emptyUsageSummary()), 200, usageCorsHeaders());
  const { accounts: usableAccounts, errors } = await decryptAccountsSafely(accounts, env);
  if (errors.length) return json({ success: false, pages: 0, workers: 0, total: 0, max: DAILY_REQUEST_LIMIT, msg: accountConfigErrorMessage(errors), errors }, 200, usageCorsHeaders());
  const usage = await loadUsageSummary(usableAccounts);
  return json(usageApiPayload(usage), 200, usageCorsHeaders());
}

function usageCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Cache-Control": "no-store",
  };
}

async function analyticsRoute(request, env) {
  const url = new URL(request.url);
  const admin = await isAdmin(request, env);
  const privacy = await readPrivacy(env);
  const privateView = admin;
  const hours = parseHours(url.searchParams.get("hours"));
  const host = privateView || privacy.publicFilters ? cleanHost(url.searchParams.get("host") || "") : "";
  const projectName = privateView || privacy.publicFilters ? cleanProjectName(url.searchParams.get("projectName") || "") : "";
  const accountId = privateView || privacy.publicFilters ? url.searchParams.get("account") || "all" : "all";
  const zoneId = privateView || privacy.publicFilters ? url.searchParams.get("zone") || "all" : "all";
  const accounts = await readAccounts(env);
  const selected = accountId === "all" ? accounts : accounts.filter((item) => item.id === accountId);
  if (!selected.length) return json({ error: "no_account", message: NO_ACCOUNT_MESSAGE }, 400);

  const decrypted = await decryptAccountsSafely(selected, env);
  if (decrypted.errors.length) return json({ error: "account_config_unreadable", message: accountConfigErrorMessage(decrypted.errors), details: decrypted.errors }, 500);
  const usableAccounts = decrypted.accounts;
  const scopedAccounts = usableAccounts.map((account) => filterAccountZones(account, zoneId));
  const analyzableAccounts = scopedAccounts.filter((account) => (account.zones || []).length);
  const results = await Promise.all(analyzableAccounts.map((account) => loadAccountAnalytics(account, hours, host)));
  const summary = mergeAnalytics(results, hours);
  const projectMetrics = projectName ? await loadWorkerProjectMetrics(usableAccounts, projectName, hours) : null;
  const workerMetrics = projectMetrics || await loadWorkerAccountMetrics(usableAccounts, hours);
  const usage = projectMetrics ? projectUsageSummary(await loadUsageSummary(usableAccounts), projectMetrics) : await loadUsageSummary(usableAccounts);
  const body = { generatedAt: beijingNow(), hours, host, projectName, zone: zoneId, accounts: results.map(stripSecrets), summary: withBeijingTimeline(summary), usage, projectMetrics, workerMetrics, analyticsAvailable: analyzableAccounts.length > 0, privacy };
  return json(privateView ? body : redactForPublic(body, privacy));
}

async function aiRoute(request, env) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  if (!hasAiBinding(env)) return json({ error: "missing_AI_binding", message: "当前 Pages 项目未绑定 Workers AI，请根据仓库 README 在 Functions 设置中添加 AI 绑定后重新部署。" }, 500);
  const body = await request.json().catch(() => ({}));
  const host = cleanHost(body.host || "");
  const projectName = cleanProjectName(body.projectName || "");
  const privacy = await readPrivacy(env);
  const verbose = Boolean(privacy.aiVerboseData);
  if (!host) return json({ error: "host_required", message: "AI 盗用风险分析必须先输入主机名，并基于筛选后的数据分析。" }, 400);
  if (!projectName) return json({ error: "project_name_required", message: "AI 分析必须输入服务名 / 项目名参数。" }, 400);
  if (!body.account || body.account === "all") return json({ error: "account_required", message: "AI 分析必须先选择一个具体账号，不能使用全部账号汇总。" }, 400);
  const zoneId = body.zone || "all";
  const accounts = await readAccounts(env);
  const selected = body.account && body.account !== "all" ? accounts.filter((item) => item.id === body.account) : accounts;
  if (!selected.length) return json({ error: "no_account", message: NO_ACCOUNT_MESSAGE }, 400);
  const usableAccounts = await Promise.all(selected.map((account) => decryptAccount(account, env)));
  const accountName = usableAccounts.map((account) => account.name || account.id).filter(Boolean).join("、") || body.account;
  const scopedAccounts = usableAccounts.map((account) => filterAccountZones(account, zoneId));
  if (!scopedAccounts.some((account) => (account.zones || []).length)) return json({ error: "no_zone_for_analysis", message: "当前账号未配置区域 ID，无法进行域名请求明细和 AI 分析。" }, 400);
  const data = await Promise.all(scopedAccounts.map((account) => loadAccountAnalytics(account, 24, host, true)));
  const summary = mergeAnalytics(data, 24);
  const projectMetrics = await loadWorkerProjectMetrics(scopedAccounts, projectName, 24);
  if (!projectMetrics.matched) return json({ error: "project_metrics_empty", message: "服务名 / 项目名参数错误，无法成功获取该服务的项目级 Workers metrics 数据。" }, 400);
  const usage = projectUsageSummary(await loadUsageSummary(scopedAccounts), projectMetrics);
  const aiInput = { host, zone: zoneId, verbose, filter: { host, account: body.account || "all", accountName, zone: zoneId, projectName }, httpRequests: withAiTimeBuckets(summary, data), projectMetrics, workerUsage: compactUsageForAI(usage), accounts: data.map(stripSecrets) };
  const prompt = buildAbusePrompt(aiInput);
  const model = env.AI_MODEL || DEFAULT_AI_MODEL;
  let aiText = extractAiText(await runAnalysisModel(env, model, prompt, verbose));
  if (!aiText) aiText = extractAiText(await runAnalysisModel(env, model, `${prompt}\n\n重要：上一次没有返回最终正文。现在只输出最终 Markdown，不要输出 reasoning，不要输出 JSON 对象。`, verbose));
  if (!aiText) return json({ error: "ai_empty_response", message: "AI 没有返回最终分析正文，请稍后重试或切换模型。" }, 502);
  const analysis = finalizeMarkdown(aiText, { accountName, host, projectName });
  return json({ model, analysis });
}

function runAnalysisModel(env, model, prompt, verbose) {
  return env.AI.run(model, {
    messages: [
      { role: "system", content: "你必须严格遵守用户要求，使用简体中文，只输出最终 Markdown，不输出思考过程、草稿、检查清单或解释你如何遵守规则。" },
      { role: "user", content: prompt },
    ],
    max_completion_tokens: verbose ? 6000 : 4096,
    temperature: 0.1,
    top_p: 0.3,
    reasoning_effort: "low",
    repetition_penalty: 1.05,
  });
}

function extractAiText(value) {
  if (typeof value === "string") return value;
  if (value?.response) return extractAiText(value.response);
  if (value?.result) return extractAiText(value.result);
  if (value?.output_text) return String(value.output_text);
  const messageContent = value?.choices?.[0]?.message?.content;
  if (Array.isArray(messageContent)) return messageContent.map((item) => item.text || item.content || "").join("\n").trim();
  if (messageContent) return String(messageContent);
  const choiceText = value?.choices?.[0]?.text;
  if (choiceText) return String(choiceText);
  if (Array.isArray(value?.output)) return value.output.map(extractAiText).filter(Boolean).join("\n").trim();
  if (Array.isArray(value?.content)) return value.content.map(extractAiText).filter(Boolean).join("\n").trim();
  if (value?.text) return String(value.text);
  if (value && typeof value === "object") return "";
  return String(value || "");
}

async function loadAccountAnalytics(account, hours, host, includeAiBuckets = false) {
  const { start, end } = timeRange(hours);
  const bucketRanges = includeAiBuckets ? buildBucketRanges(start, end) : [];
  const zoneResults = await Promise.all(account.zones.map((zone) => queryZone(account, zone, start, end, hours, host, bucketRanges)));
  return {
    id: account.id,
    name: account.name,
    zones: zoneResults,
    totals: mergeAnalytics(zoneResults, hours),
  };
}

async function loadUsageSummary(accounts) {
  const dayStart = new Date();
  dayStart.setUTCHours(0, 0, 0, 0);
  const configured = accounts.filter((account) => account.accountId);
  const rows = await Promise.all(configured.map((account) => queryAccountUsage(account, dayStart.toISOString(), new Date().toISOString()).catch((error) => ({ accountId: account.id, name: account.name, workers: 0, pages: 0, error: error.message }))));
  const workers = rows.reduce((sum, row) => sum + (row.workers || 0), 0);
  const pages = rows.reduce((sum, row) => sum + (row.pages || 0), 0);
  const limit = configured.length * DAILY_REQUEST_LIMIT;
  const failedAccounts = rows.filter((row) => row.error).length;
  return { workers, pages, total: workers + pages, limit, configuredAccounts: configured.length, missingAccounts: accounts.length - configured.length, failedAccounts, accounts: rows };
}

function emptyUsageSummary() {
  return { workers: 0, pages: 0, total: 0, limit: DAILY_REQUEST_LIMIT, configuredAccounts: 0, missingAccounts: 0, failedAccounts: 0, accounts: [] };
}

function usageApiPayload(usage) {
  const max = usage.limit || DAILY_REQUEST_LIMIT;
  const queriedAccounts = Number(usage.configuredAccounts || 0) - Number(usage.failedAccounts || 0);
  return {
    success: queriedAccounts > 0,
    pages: Number(usage.pages || 0),
    workers: Number(usage.workers || 0),
    total: Number(usage.total || 0),
    max,
    limit: max,
    configuredAccounts: Number(usage.configuredAccounts || 0),
    missingAccounts: Number(usage.missingAccounts || 0),
    failedAccounts: Number(usage.failedAccounts || 0),
    resources: emptyResourcesUsage(),
    UpdateTime: Date.now(),
    msg: queriedAccounts > 0 ? "✅ 成功加载免费额度使用数据" : "未配置可查询 Account ID 的账号",
    generatedAt: beijingNow(),
  };
}

function emptyResourcesUsage() {
  return {
    d1: { rowsRead: 0, rowsReadLimit: 25000000, rowsWritten: 0, rowsWrittenLimit: 500000, readQueries: 0, writeQueries: 0, storageBytes: 0, storageLimitBytes: 26843545600, databases: 0, period: "day" },
    kv: { reads: 0, readsLimit: 500000, writes: 0, writesLimit: 5000, deletes: 0, deletesLimit: 5000, lists: 0, listsLimit: 5000, operations: 0, storageBytes: 0, storageLimitBytes: 5368709120, keys: 0, namespaces: 0, period: "day" },
    r2: { classA: 0, classALimit: 5000000, classB: 0, classBLimit: 50000000, free: 0, other: 0, operations: 0, storageBytes: 0, storageLimitBytes: 53687091200, objects: 0, buckets: 0, period: "month" },
  };
}

async function queryAccountUsage(account, start, end) {
  const query = `query AccountRequestUsage($accountTag: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) { viewer { accounts(filter: { accountTag: $accountTag }) { pages: pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } } workers: workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } } } } }`;
  const payload = await cfGraphql(account.token, query, { accountTag: account.accountId, filter: { datetime_geq: start, datetime_leq: end } });
  const data = payload.data?.viewer?.accounts?.[0] || {};
  return {
    accountId: account.id,
    name: account.name,
    workers: sumRequests(data.workers),
    pages: sumRequests(data.pages),
  };
}

function sumRequests(rows) {
  return (rows || []).reduce((total, row) => total + Number(row?.sum?.requests || 0), 0);
}

async function loadWorkerAccountMetrics(accounts, hours) {
  const { start, end } = timeRange(hours);
  const configured = accounts.filter((account) => account.accountId);
  const rows = await Promise.all(configured.map((account) => queryWorkerAccountMetrics(account, start, end).catch((error) => ({ accountId: account.id, name: account.name, totalRequests: 0, timeline: [], fourHourBuckets: [], error: error.message }))));
  const timeline = mergeProjectTimeline(rows);
  return {
    projectName: "",
    totalRequests: timeline.reduce((sum, point) => sum + Number(point.count || 0), 0),
    matched: timeline.some((point) => Number(point.count || 0) > 0),
    timeline,
    fourHourBuckets: mergeProjectBuckets(rows),
    accounts: rows,
    note: "未指定 Service 名称，按当前筛选账号汇总 Workers 请求折线。",
  };
}

async function queryWorkerAccountMetrics(account, start, end) {
  const query = `query WorkerAccountMetrics($accountTag: string, $datetimeStart: string, $datetimeEnd: string) { viewer { accounts(filter: { accountTag: $accountTag }) { workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd }) { sum { requests errors subrequests } dimensions { datetime status } } } } }`;
  const payload = await cfGraphql(account.token, query, { accountTag: account.accountId, datetimeStart: start, datetimeEnd: end });
  const rows = payload.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive || [];
  const timeline = buildProjectTimeline(rows, start, end);
  return {
    accountId: account.id,
    name: account.name,
    totalRequests: timeline.reduce((sum, point) => sum + point.count, 0),
    timeline,
    fourHourBuckets: buildProjectFourHourBuckets(timeline),
  };
}

async function loadWorkerProjectMetrics(accounts, projectName, hours) {
  const { start, end } = timeRange(hours);
  const configured = accounts.filter((account) => account.accountId);
  const rows = await Promise.all(configured.map((account) => queryWorkerProjectMetrics(account, projectName, start, end).catch((error) => ({ accountId: account.id, name: account.name, projectName, totalRequests: 0, timeline: [], fourHourBuckets: [], error: error.message }))));
  const totalRequests = rows.reduce((sum, row) => sum + Number(row.totalRequests || 0), 0);
  const matched = totalRequests > 0;
  return {
    projectName,
    totalRequests,
    matched,
    timeline: mergeProjectTimeline(rows),
    fourHourBuckets: mergeProjectBuckets(rows),
    accounts: rows,
    note: matched ? "已匹配指定 Service 的项目级 Workers metrics。" : "指定 Service 当前时间范围内无匹配请求数据。",
  };
}

function projectUsageSummary(accountUsage, projectMetrics) {
  return {
    ...accountUsage,
    workers: projectMetrics.totalRequests || 0,
    pages: 0,
    total: projectMetrics.totalRequests || 0,
    projectName: projectMetrics.projectName,
    projectScoped: true,
    projectMatched: Boolean(projectMetrics.matched),
  };
}

async function queryWorkerProjectMetrics(account, projectName, start, end) {
  const query = `query WorkerProjectMetrics($accountTag: string, $datetimeStart: string, $datetimeEnd: string, $scriptName: string) { viewer { accounts(filter: { accountTag: $accountTag }) { workersInvocationsAdaptive(limit: 10000, filter: { scriptName: $scriptName, datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd }) { sum { requests errors subrequests } dimensions { datetime scriptName status } } } } }`;
  const payload = await cfGraphql(account.token, query, { accountTag: account.accountId, datetimeStart: start, datetimeEnd: end, scriptName: projectName });
  const rows = payload.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive || [];
  const timeline = buildProjectTimeline(rows, start, end);
  return {
    accountId: account.id,
    name: account.name,
    projectName,
    totalRequests: timeline.reduce((sum, point) => sum + point.count, 0),
    timeline,
    fourHourBuckets: buildProjectFourHourBuckets(timeline),
  };
}

function buildProjectTimeline(rows, start, end) {
  const map = new Map();
  for (const row of rows || []) {
    const time = row.dimensions?.datetime;
    if (!time) continue;
    const key = new Date(floorTime(new Date(time).getTime(), 60 * 60 * 1000)).toISOString().replace(/\.000Z$/, "Z");
    const old = map.get(key) || { time: formatBeijingTime(key), count: 0, errors: 0, subrequests: 0 };
    old.count += Number(row.sum?.requests || 0);
    old.errors += Number(row.sum?.errors || 0);
    old.subrequests += Number(row.sum?.subrequests || 0);
    map.set(key, old);
  }
  const points = [];
  for (let t = floorTime(new Date(start).getTime(), 60 * 60 * 1000); t < new Date(end).getTime(); t += 60 * 60 * 1000) {
    const key = new Date(t).toISOString().replace(/\.000Z$/, "Z");
    points.push(map.get(key) || { time: formatBeijingTime(key), count: 0, errors: 0, subrequests: 0 });
  }
  return points;
}

function buildProjectFourHourBuckets(timeline) {
  const buckets = [];
  for (let index = 0; index < 6; index += 1) {
    const slice = timeline.slice(index * 4, index * 4 + 4);
    buckets.push({
      start: slice[0]?.time || "",
      end: slice[slice.length - 1]?.time || "",
      count: slice.reduce((sum, point) => sum + Number(point.count || 0), 0),
      errors: slice.reduce((sum, point) => sum + Number(point.errors || 0), 0),
      subrequests: slice.reduce((sum, point) => sum + Number(point.subrequests || 0), 0),
    });
  }
  return buckets;
}

function mergeProjectTimeline(rows) {
  const points = new Map();
  for (const row of rows || []) {
    for (const point of row.timeline || []) {
      const key = beijingTimelineKey(point.time);
      const old = points.get(key) || { time: point.time, count: 0, errors: 0, subrequests: 0 };
      old.count += Number(point.count || 0);
      old.errors += Number(point.errors || 0);
      old.subrequests += Number(point.subrequests || 0);
      points.set(key, old);
    }
  }
  return [...points.values()].sort((a, b) => a.time.localeCompare(b.time));
}

function beijingTimelineKey(value) {
  return String(value || "").replace(/ GMT\+8$/, "");
}

function mergeProjectBuckets(rows) {
  const buckets = [];
  for (const row of rows || []) {
    for (let index = 0; index < (row.fourHourBuckets || []).length; index += 1) {
      const point = row.fourHourBuckets[index];
      if (!buckets[index]) buckets[index] = { start: point.start, end: point.end, count: 0, errors: 0, subrequests: 0 };
      buckets[index].count += Number(point.count || 0);
      buckets[index].errors += Number(point.errors || 0);
      buckets[index].subrequests += Number(point.subrequests || 0);
    }
  }
  return buckets;
}

function compactUsageForAI(usage) {
  return {
    workers: usage.workers,
    pages: usage.pages,
    totalWorkersAndPages: usage.total,
    workerFreeDailyLimit: usage.limit,
    workerUsagePercent: usage.limit ? Number(((usage.workers / usage.limit) * 100).toFixed(2)) : null,
    totalWorkersPagesUsagePercent: usage.limit ? Number(((usage.total / usage.limit) * 100).toFixed(2)) : null,
    configuredAccounts: usage.configuredAccounts,
    missingAccounts: usage.missingAccounts,
    projectName: usage.projectName || "",
    projectScoped: Boolean(usage.projectScoped),
    projectMatched: Boolean(usage.projectMatched),
    scope: usage.projectScoped ? (usage.projectMatched ? "已按当前选中账号和指定 Service 统计项目级 Workers metrics；Pages 计为 0。" : "已按当前选中账号和指定 Service 查询项目级 Workers metrics，当前时间范围内没有匹配请求数据。") : "未指定 Service 名称，Workers/Pages 为账号级汇总。",
    note: "80000/100000 免费额度判断只能参考 workers 字段或 workerUsagePercent，不能参考 httpRequests.totalRequests。httpRequests 是 Zone HTTP 总请求，可能包含普通站点请求。",
  };
}

function withAiTimeBuckets(summary, accountData) {
  return {
    ...summary,
    timeline: (summary.timeline || []).map((point) => ({ ...point, time: formatBeijingTime(point.time) })),
    fourHourBuckets: buildFourHourBuckets(accountData).map((bucket) => ({
      ...bucket,
      start: formatBeijingTime(bucket.start),
      end: formatBeijingTime(bucket.end),
    })),
  };
}

function withBeijingTimeline(summary) {
  return {
    ...summary,
    timeline: (summary.timeline || []).map((point) => ({ ...point, time: formatBeijingTime(point.time) })),
  };
}

function buildBucketRanges(start, end) {
  const startMs = new Date(start).getTime();
  const endMs = new Date(end).getTime();
  const bucketMs = 4 * 60 * 60 * 1000;
  return Array.from({ length: 6 }, (_, index) => {
    const bucketStart = new Date(startMs + index * bucketMs);
    const bucketEnd = new Date(Math.min(bucketStart.getTime() + bucketMs, endMs));
    return {
      start: bucketStart.toISOString().replace(/\.000Z$/, "Z"),
      end: bucketEnd.toISOString().replace(/\.000Z$/, "Z"),
    };
  });
}

function formatBeijingTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "");
  const beijing = new Date(date.getTime() + 8 * 60 * 60 * 1000);
  const yyyy = beijing.getUTCFullYear();
  const mm = String(beijing.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(beijing.getUTCDate()).padStart(2, "0");
  const hh = String(beijing.getUTCHours()).padStart(2, "0");
  const mi = String(beijing.getUTCMinutes()).padStart(2, "0");
  const ss = String(beijing.getUTCSeconds()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${mi}:${ss} GMT+8`;
}

function beijingNow() {
  return formatBeijingTime(new Date().toISOString());
}

function buildFourHourBuckets(accountData) {
  const buckets = [];
  if (Array.isArray(accountData) && accountData.length) {
    for (const account of accountData) {
      for (const zone of account.zones || []) {
        const zoneBuckets = zone.aiBuckets || [];
        if (!buckets.length && zoneBuckets.length) {
          for (const source of zoneBuckets) {
            buckets.push({
              start: source.start,
              end: source.end,
              count: 0,
              bytes: 0,
              topIPs: [],
              topHosts: [],
            });
          }
        }
        for (let index = 0; index < buckets.length; index += 1) {
          const source = zoneBuckets[index];
          if (!source) continue;
          const bucket = buckets[index];
          bucket.count += Number(source.count || 0);
          bucket.bytes += Number(source.bytes || 0);
          bucket.topIPs = mergeRankedEntries(bucket.topIPs, source.topIPs, (entry) => entry.dimensions?.clientIP, "clientIP", "clientCountryName");
          bucket.topHosts = mergeRankedEntries(bucket.topHosts, source.topHosts, (entry) => entry.dimensions?.clientRequestHTTPHost, "clientRequestHTTPHost");
        }
      }
    }
  }
  return buckets;
}

function mergeRankedEntries(target, source, keyFn, ...dimensionKeys) {
  const map = new Map();
  for (const entry of target || []) {
    const key = keyFn(entry);
    if (!key) continue;
    map.set(key, { count: Number(entry.count || 0), dimensions: { ...entry.dimensions } });
  }
  for (const entry of source || []) {
    const key = keyFn(entry);
    if (!key) continue;
    const current = map.get(key) || { count: 0, dimensions: {} };
    current.count += Number(entry.count || 0);
    for (const dimKey of dimensionKeys) {
      if (entry.dimensions?.[dimKey] != null) current.dimensions[dimKey] = entry.dimensions[dimKey];
    }
    map.set(key, current);
  }
  return [...map.values()].sort((a, b) => b.count - a.count).slice(0, 20);
}

function filterAccountZones(account, zoneId) {
  if (!zoneId || zoneId === "all") return account;
  return { ...account, zones: (account.zones || []).filter((zone) => zone.id === zoneId) };
}

async function queryZone(account, zone, start, end, hours, host, bucketRanges = []) {
  const useMinute = hours === 1;
  const timeField = useMinute ? "datetimeMinute" : "datetimeHour";
  const orderField = useMinute ? "datetimeMinute_ASC" : "datetimeHour_ASC";
  const filter = { datetime_geq: start, datetime_lt: end, requestSource: "eyeball" };
  if (host) filter.clientRequestHTTPHost = host;
  const query = `query ZoneRequestAnalytics($zoneTag: string, $filter: filter) { viewer { zones(filter: { zoneTag: $zoneTag }) { totals: httpRequestsAdaptiveGroups(limit: 1, filter: $filter) { count sum { edgeResponseBytes } } timeline: httpRequestsAdaptiveGroups(limit: 2000, filter: $filter, orderBy: [${orderField}]) { count sum { edgeResponseBytes } dimensions { ${timeField} } } topIPs: httpRequestsAdaptiveGroups(limit: 20, filter: $filter, orderBy: [count_DESC]) { count dimensions { clientIP clientCountryName } } topHosts: httpRequestsAdaptiveGroups(limit: 20, filter: $filter, orderBy: [count_DESC]) { count dimensions { clientRequestHTTPHost } } topCountries: httpRequestsAdaptiveGroups(limit: 200, filter: $filter, orderBy: [count_DESC]) { count dimensions { clientCountryName } } } } }`;
  const payload = await cfGraphql(account.token, query, { zoneTag: zone.zoneTag, filter });
  const zoneData = payload.data?.viewer?.zones?.[0] || {};
  const aiBuckets = bucketRanges.length ? await Promise.all(bucketRanges.map((range) => queryZoneBucket(account, zone.zoneTag, host, range.start, range.end))) : [];
  return {
    id: zone.id,
    name: zone.name || "未命名区域",
    totalRequests: zoneData.totals?.[0]?.count || 0,
    totalBytes: zoneData.totals?.[0]?.sum?.edgeResponseBytes || 0,
    timeline: fillTimeline(zoneData.timeline || [], hours, timeField, start, end),
    topIPs: zoneData.topIPs || [],
    topHosts: zoneData.topHosts || [],
    topCountries: zoneData.topCountries || [],
    aiBuckets,
    errors: payload.errors || null,
  };
}

async function queryZoneBucket(account, zoneTag, host, start, end) {
  const filter = { datetime_geq: start, datetime_lt: end, requestSource: "eyeball" };
  if (host) filter.clientRequestHTTPHost = host;
  const query = `query ZoneBucketAnalytics($zoneTag: string, $filter: filter) { viewer { zones(filter: { zoneTag: $zoneTag }) { totals: httpRequestsAdaptiveGroups(limit: 1, filter: $filter) { count sum { edgeResponseBytes } } topIPs: httpRequestsAdaptiveGroups(limit: 20, filter: $filter, orderBy: [count_DESC]) { count dimensions { clientIP clientCountryName } } topHosts: httpRequestsAdaptiveGroups(limit: 20, filter: $filter, orderBy: [count_DESC]) { count dimensions { clientRequestHTTPHost } } } } }`;
  const payload = await cfGraphql(account.token, query, { zoneTag, filter });
  const zoneData = payload.data?.viewer?.zones?.[0] || {};
  return {
    start,
    end,
    count: zoneData.totals?.[0]?.count || 0,
    bytes: zoneData.totals?.[0]?.sum?.edgeResponseBytes || 0,
    topIPs: zoneData.topIPs || [],
    topHosts: zoneData.topHosts || [],
  };
}

async function cfGraphql(token, query, variables) {
  const res = await fetch(GRAPHQL_ENDPOINT, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.errors?.[0]?.message || `Cloudflare GraphQL ${res.status}`);
  return data;
}

function mergeAnalytics(items, hours) {
  const points = new Map();
  const topIPs = new Map();
  const topHosts = new Map();
  const topCountries = new Map();
  let totalRequests = 0;
  let totalBytes = 0;
  for (const item of items) {
    const totals = item.totals || item;
    totalRequests += totals.totalRequests || 0;
    totalBytes += totals.totalBytes || 0;
    for (const point of totals.timeline || []) {
      const old = points.get(point.time) || { time: point.time, count: 0, bytes: 0 };
      old.count += point.count || 0;
      old.bytes += point.bytes || 0;
      points.set(point.time, old);
    }
    for (const entry of totals.topIPs || []) {
      const ip = entry.dimensions?.clientIP;
      if (!ip) continue;
      const old = topIPs.get(ip) || { count: 0, dimensions: { clientIP: ip, clientCountryName: entry.dimensions?.clientCountryName || "" } };
      old.count += entry.count || 0;
      topIPs.set(ip, old);
    }
    for (const entry of totals.topHosts || []) {
      const hostname = entry.dimensions?.clientRequestHTTPHost;
      if (!hostname) continue;
      const old = topHosts.get(hostname) || { count: 0, dimensions: { clientRequestHTTPHost: hostname } };
      old.count += entry.count || 0;
      topHosts.set(hostname, old);
    }
    for (const entry of totals.topCountries || []) {
      const country = entry.dimensions?.clientCountryName || "未知";
      const old = topCountries.get(country) || { count: 0, dimensions: { clientCountryName: country } };
      old.count += entry.count || 0;
      topCountries.set(country, old);
    }
  }
  return {
    totalRequests,
    totalBytes,
    timeline: [...points.values()].sort((a, b) => a.time.localeCompare(b.time)),
    topIPs: [...topIPs.values()].sort((a, b) => b.count - a.count).slice(0, 20),
    topHosts: [...topHosts.values()].sort((a, b) => b.count - a.count).slice(0, 20),
    topCountries: [...topCountries.values()].sort((a, b) => b.count - a.count).slice(0, 80),
    rangeHours: hours,
  };
}

function fillTimeline(rows, hours, timeField, start, end) {
  const stepMs = hours === 1 ? 60 * 1000 : 60 * 60 * 1000;
  const map = new Map();
  for (const row of rows) {
    const time = row.dimensions?.[timeField];
    if (!time) continue;
    map.set(time, { time, count: row.count || 0, bytes: row.sum?.edgeResponseBytes || 0 });
  }
  const points = [];
  for (let t = floorTime(new Date(start).getTime(), stepMs); t < new Date(end).getTime(); t += stepMs) {
    const key = new Date(t).toISOString().replace(/\.000Z$/, "Z");
    points.push(map.get(key) || { time: key, count: 0, bytes: 0 });
  }
  return points;
}

function buildAbusePrompt(input) {
  const compact = JSON.stringify(input);
  const verboseRule = input.verbose
    ? "最高优先级要求：直接输出完整数据与分析结果，按固定 Markdown 模板输出。不要输出思考过程、不要解释规则、不要把模板说明写进正文。"
    : "最高优先级要求：只输出分析结果，不要复述完整原始数据；但必须完整查看 24 小时趋势、6 段每 4 小时细分、Top IP、Top Host、国家/地区和 Workers 指标，并在依据中引用关键变化。";
  const outputTemplate = input.verbose
    ? `当前分析账号：<账号>
当前分析域名：<域名>
当前分析服务名：<服务名>
### 完整数据
#### Workers / Pages 用量
#### HTTP 汇总
#### 每 4 小时细分
#### 24 小时趋势
#### Top IP
#### Top Host
#### 国家 / 地区
#### 账号与区域
### 结论
### 风险等级
### 依据
### 可能原因
### 建议`
    : `当前分析账号：<账号>
当前分析域名：<域名>
当前分析服务名：<服务名>
### 结论
### 风险等级
### 依据
### 可能原因
### 建议`;
  return `你是代理节点流量分析助手。必须只使用简体中文输出。

唯一目标：判断当前域名对应的代理节点、订阅链接、节点地址或配置是否可能外泄并被他人连接使用。

最高原则：降低误报是最高优先级。没有连续高位、多个高请求 IP、来源持续扩散、Workers 用量异常等强证据时，默认判断为正常自用、客户端自动行为、爬虫扫描或普通请求噪声。不要因为单个峰值、单个国家/地区、单个高占比 IP 推断节点外泄。

${verboseRule}

分析范围：
- 只分析输入数据中当前账号、当前区域、当前域名、当前服务名的过去 24 小时数据。
- 不要假设其他域名、其他账号、全站流量或历史基线。
- 如果缺少历史基线，不要做确定性判断。

数据口径：
- httpRequests.totalRequests 是当前域名 HTTP 总请求，可能包含网页/API、静态资源、客户端探测、爬虫、扫描器，不等同于代理真实使用量。
- httpRequests.totalBytes 是当前域名边缘响应流量，必须和请求数一起看；高请求但低流量更像探测、测速、保活或订阅刷新，不等同于真实代理大流量使用。
- httpRequests.timeline 是逐小时趋势，用于判断峰值、回落和持续性。
- httpRequests.fourHourBuckets 是 6 段每 4 小时数据，必须参与判断。
- 每个 4 小时段的 count 与 bytes 必须一起判断；如果 count 偏高但 bytes 很低或 bytes/request 很低，优先解释为探测/保活/配置刷新。
- topIPs 用于判断来源集中还是扩散。
- topHosts 只作为流量分布参考。
- topCountries 是客户端国家/地区聚合，用于辅助判断来源是否扩散。
- topCountries 只能作为辅助信号，不能单独作为节点外泄证据。
- workerUsage.workers 才用于判断 Workers 请求额度，不要用 httpRequests.totalRequests 判断 Workers 免费额度。
- 如果输入包含 projectMetrics，说明用户指定了可观测性 Service 名称；此时必须优先使用 projectMetrics 和 workerUsage 中的项目级 Workers metrics 判断该服务。
- 如果 projectMetrics.matched 为 false 或 workerUsage.projectMatched 为 false，必须说明当前服务名在该时间范围内没有匹配项目级 Workers 请求，不要改用账号级 Workers/Pages 汇总做该服务风险判断。
- 输入中的时间已转换为北京时间 GMT+8，输出也按北京时间描述。
- Workers / Pages 必须保留英文。

判断顺序：
1. 先看 6 段 4 小时分段是否连续高位，还是单一高峰后回落。
2. 再看 Top IP 是否由单一/少数固定 IP 主导，还是多个高请求 IP 同时存在。
3. 再看国家/地区是否只是辅助扩散信号。
4. 最后结合 Workers 用量或项目级 Workers metrics 判断是否存在资源异常。

默认正常的情况：
- 总请求量低于 3000。
- 多数 Top IP 单 IP 请求数低于 1000。
- 只有一个 4 小时段突出，前后段低或为 0。
- 最大 IP 占比很高且来源稳定。
- 高峰段对应用户实际上网时段。
- 最大 IP 是用户出口 IP 或接近用户当前出口。
- 国家/地区有分布，但单 IP 请求不高且没有连续高位。
- Workers 用量很低。

需要观察的情况：
- 总请求量偏高，但只有单个峰值或不足 2 个连续高位分段。
- 单个 IP 超过 1000，但仍主要集中在一个 IP。
- 来源略有扩散，但没有多个高请求 IP 同时存在。
- 无法确认最大 IP 是否为用户本人出口。
- 客户端探测/保活较频繁，但还不像外泄。
- 请求数偏高但边缘响应流量很少，或流量与请求数不匹配。

疑似节点外泄必须同时具备多项强证据：
- 总请求量明显偏高。
- 多个 Top IP 单 IP 请求数超过 1000。
- 至少连续 2 个 4 小时段维持高位。
- 来源从集中变为明显扩散。
- 多国家/地区来源同时高频，并且不是低量噪声。
- 来源形态不像固定出口、家庭宽带、移动网络或常用反代入口。
- Workers 用量明显升高或持续增长。
- 峰值没有回落，呈持续高位。

高风险节点外泄必须满足更强证据：
- 多个 4 小时段连续高位。
- 多个高请求 IP 同时存在。
- 来源明显扩散且持续。
- 请求量和 Workers 用量都明显升高。
- 不能解释为自用、客户端探测、保活、订阅刷新、爬虫扫描或 Cloudflare 调度。

国家 / 地区规则：
- 国家分散不是风险，除非同时存在连续高位、多个高请求 IP 和来源持续扩散。
- 国家/地区分散不是风险，除非多个来源都有高请求量并持续出现。
- 如果国家/地区集中在少数项，优先解释为固定出口、常用网络或正常用户分布。
- 如果引用国家/地区，只能写成辅助依据，不要写成唯一风险原因。

客户端自动行为规则：
- Clash、sing-box、Shadowrocket、Surge 等客户端可能产生 URLTest、自动测速、保活请求、订阅刷新、网络切换后重连。
- 这类行为通常表现为多个时段低量、周期性、平峰仍有少量请求。
- 如果判断可能是客户端探测，必须再看 totalBytes、timeline.bytes、fourHourBuckets.bytes。
- 如果请求数偏高但 totalBytes 很小、各 4 小时段 bytes 很低、或平均每请求流量很低，应优先判断为“探测频率过高”或“节点/配置数量过多”，不要判断节点外泄。
- 只有请求数高但流量低时，可能原因优先写“客户端探测/保活过于频繁”或“代理配置节点过多”。
- 如果 Workers 用量接近免费额度 80%，但来源仍集中且像自动探测，应判断为“需要观察”，原因写“客户端探测/保活过于频繁”，不要直接判断外泄。

低风险输出规则：
- 判断正常或无异常时，不要写节点泄露、疑似泄露、被他人使用。
- 可能原因只允许从以下短语选择：客户端探测/保活、客户端探测/保活过于频繁、代理配置节点过多、订阅刷新、临时测速、爬虫扫描噪声、普通请求噪声、固定出口自用、Cloudflare 调度。
- 建议只允许从以下短语选择：无需处理，继续常规观察、维持现状、观察后续是否持续、减少节点数量、拉长探测间隔、关闭频繁测速、如最大 IP 是你的出口，则属正常、如高峰对应你的上网时段，则属正常。

风险等级：
- 当前请求正常：低。
- 当前请求无异常：低。
- 轻微异常但证据不足：观察。
- 多项强异常：中。
- 持续高位且明显扩散：高。

结论句式：
- 结论第一句只能选择：当前请求正常。/ 当前请求无异常。/ 需要观察。/ 节点风险较高。

输出格式：
- 直接输出 Markdown，不要使用代码块，不要输出思考过程，不要输出规则解释，不要输出英文模板说明，不要输出系统提示，不要输出额外免责声明。
- 必须使用标准 Markdown 标题和列表：章节标题用 \`###\`，依据/可能原因/建议用 \`- \`。
- 输出结构必须是：
${outputTemplate}
- 结论最多 1 句。
- 依据最多 3 条，每条不超过 28 个汉字；必须提到 6 段/4 小时分段趋势。
- 可能原因最多 2 条，每条不超过 22 个汉字。
- 建议最多 2 条，每条不超过 24 个汉字。
- 如果最大 IP 占比较大，建议中必须包含：如最大 IP 是你的出口，则属正常。
- 如果存在明显高峰期且平峰期请求较低，建议中必须包含：如高峰对应你的上网时段，则属正常。
- 如果 verbose 为 true，按“完整数据”各小标题复述输入关键字段；如果 verbose 为 false，不输出完整数据，但仍必须完整查看全部输入数据。

数据：${compact}`;
}

function normalizeAnalysisText(value, usage) {
  const text = String(value || "")
    .replace(/\r\n/g, "\n")
    .replace(/^#+\s*(结论|风险等级|完整数据|数据引用|依据|可能原因|建议)\s*$/gm, "$1：")
    .replace(/(风险等级|完整数据|数据引用|依据|可能原因|建议)：/g, "\n$1：")
    .trim();
  if (!text) return text;
  const fields = ["结论", "风险等级", "完整数据", "数据引用", "依据", "可能原因", "建议"];
  const result = new Map();
  let current = "";
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    const match = line.match(/^(结论|风险等级|完整数据|数据引用|依据|可能原因|建议)：\s*(.*)$/);
    if (match) {
      current = match[1];
      if (!result.has(current)) result.set(current, match[2].trim());
      continue;
    }
    if (current && result.has(current) && !fields.every((field) => result.has(field))) {
      result.set(current, `${result.get(current)} ${line}`.trim());
    }
  }
  if (/Top Host 不是预期主机|不法行为|```/.test(text)) return fallbackAnalysis(usage);
  const workerPct = usage?.limit ? (usage.workers / usage.limit) * 100 : 0;
  if (workerPct < 80 && /(80000|80%|百分之八十|接近免费|达到.*免费|额度 80|额度80)/.test(text)) return fallbackAnalysis(usage);
  if (workerPct < 10 && /风险等级：低/.test(text) && /降低订阅刷新频率|改用手动选择|无探测配置|关闭.*测速|关闭频繁探测|拉长探测间隔/.test(text)) return fallbackAnalysis(usage);
  const output = fields.filter((field) => result.has(field)).map((field) => field === "完整数据" ? `${field}：${result.get(field)}` : `${field}：${trimField(result.get(field))}`);
  if (output.length) return output.join("\n");
  return "";
}

function fallbackAnalysis(usage) {
  const incomplete = usage.missingAccounts > 0 || !usage.configuredAccounts;
  const workerPct = usage.limit ? (usage.workers / usage.limit) * 100 : 0;
  const nearLimit = workerPct >= 80;
  return [
    nearLimit ? "结论：Workers 额度接近高位，更像客户端探测或配置刷新导致的高频请求，需要观察。" : "结论：Workers 额度使用率较低，当前不接近免费额度风险。",
    `风险等级：${nearLimit ? "观察" : "低"}。`,
    `依据：Workers 当日请求 ${usage.workers || 0}，Pages 当日请求 ${usage.pages || 0}，共享额度使用率 ${usage.limit ? workerPct.toFixed(1) + "%" : "未配置"}${incomplete ? "；部分账号未配置 Account ID，额度数据不完整" : ""}。`,
    nearLimit ? "可能原因：客户端探测、测速、配置刷新或代理配置较多。" : "可能原因：正常代理流量、少量客户端探测、测速或配置刷新。",
    nearLimit ? "建议：减少代理配置数量、关闭频繁探测、改用无探测配置、拉长探测间隔。" : incomplete ? "建议：补全 Account ID 后再按 Workers 请求额度判断是否接近免费额度。" : "建议：继续观察当前主机名的 Workers 用量、来源变化和每小时趋势。",
  ].join("\n");
}

function finalizeAnalysis(text, host) {
  const note = "AI 分析仅供参考。";
  const cleaned = String(text || "").replace(/\n*(仅供参考。?|AI (输出|分析)仅供参考[\s\S]*)\s*$/g, "").trim();
  const sections = parseAnalysisSections(cleaned);
  return [
    `当前分析域名：${host || "未指定"}`,
    "",
    "### 结论",
    sections.conclusion || "需要观察。",
    "",
    "### 风险等级",
    sections.risk || "观察。",
    "",
    ...(sections.fullData ? ["### 完整数据", sections.fullData, ""] : []),
    ...(sections.dataRefs.length ? ["### 数据引用", formatList(sections.dataRefs), ""] : []),
    "### 依据",
    formatList(sections.basis),
    "",
    "### 可能原因",
    formatList(sections.causes),
    "",
    "### 建议",
    formatList(sections.suggestions),
    "",
    note,
  ].join("\n");
}

function finalizeMarkdown(value, context) {
  const note = "AI 分析仅供参考。";
  let text = cleanAiMarkdown(value);
  text = text.replace(/工作者/g, "Workers").replace(/页面函数/g, "Pages Functions").replace(/页面请求/g, "Pages 请求");
  text = text.replace(/^(当前分析账号|当前分析域名|当前分析服务名)：.*\n?/gm, "").trim();
  text = `当前分析账号：${context?.accountName || "未指定"}\n当前分析域名：${context?.host || "未指定"}\n当前分析服务名：${context?.projectName || "未指定"}\n\n${text}`;
  text = text.replace(/\n*(仅供参考。?|AI (输出|分析)仅供参考[\s\S]*)\s*$/g, "").trim();
  return `${text}\n\n${note}`;
}

function cleanAiMarkdown(value) {
  let text = String(value || "").replace(/```[a-z]*\n?|```/gi, "").replace(/<br\s*\/?>/gi, "\n").trim();
  const cutMarkers = [
    "输出错误:",
    "Output Structure Requirement:",
    "Content Requirements:",
    "Data Interpretation Confirmation:",
    "Ready to generate.",
    "thought process ends.",
    "<final_output_generation>",
    "<｜end▁of▁thinking｜>",
    "<|endofthink|>",
    "(系统提示：",
    "***免责声明",
    "免责声明：",
    "*(注：",
    "One detail:",
    "Drafting final strings carefully.",
    "Response generation starts now.",
    "Note on language:",
    "Check header capitalization:",
    "All set.",
    "thought process ends.",
  ];
  let cutAt = text.length;
  for (const marker of cutMarkers) {
    const index = text.indexOf(marker);
    if (index >= 0 && index < cutAt) cutAt = index;
  }
  text = text.slice(0, cutAt).trim();
  const badLine = text.split("\n").findIndex((line) => /^(\*{3,}|---+|\[?\(?系统提示|One detail:|Output Structure Requirement:|Content Requirements:|Data Interpretation Confirmation:)/.test(line.trim()));
  if (badLine >= 0) text = text.split("\n").slice(0, badLine).join("\n").trim();
  return text;
}

function parseAnalysisSections(text) {
  return {
    conclusion: extractField(text, "结论"),
    risk: extractField(text, "风险等级"),
    fullData: extractField(text, "完整数据"),
    dataRefs: splitItems(extractField(text, "数据引用")),
    basis: splitItems(extractField(text, "依据")),
    causes: splitItems(extractField(text, "可能原因")),
    suggestions: splitItems(extractField(text, "建议")),
  };
}

function extractField(text, field) {
  const fields = "结论|风险等级|完整数据|数据引用|依据|可能原因|建议";
  const match = String(text || "").match(new RegExp(`${field}：([\\s\\S]*?)(?=\\n?(?:${fields})：|$)`));
  return match ? match[1].trim() : "";
}

function splitItems(value) {
  const items = String(value || "")
    .replace(/；/g, ";")
    .split(/(?:^|\s)(?:\d+[.、]\s+|[-*]\s+)|;/)
    .map((item) => item.replace(/^\d+[.、]\s*/, "").trim())
    .filter(Boolean)
    .slice(0, 4);
  return mergeBrokenPercentItems(items);
}

function mergeBrokenPercentItems(items) {
  const merged = [];
  for (const item of items) {
    if (/^\d+(?:\.\d+)?%[。.]?$/.test(item) && merged.length) merged[merged.length - 1] = `${merged[merged.length - 1]} ${item}`;
    else merged.push(item);
  }
  return merged;
}

function formatList(items) {
  const list = items?.length ? items : ["暂无明确异常，继续观察。"];
  return list.map((item) => `- ${item}`).join("\n");
}

function trimField(value) {
  const text = String(value || "")
    .split(/[|｜]/)[0]
    .replace(/该问题的完整代码.*$/g, "")
    .replace(/完整代码.*$/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return text.length > 180 ? `${text.slice(0, 180)}...` : text;
}

async function validateAccountConfig(input) {
  const zones = Array.isArray(input.zones) ? input.zones : [];
  const token = String(input.token || "").trim();
  const accountId = String(input.accountId || "").trim();
  const zoneIds = zones.map((zone) => String(zone.zoneTag || "").trim()).filter(Boolean);
  if (!input.name || !token || (!zoneIds.length && !accountId)) throw new Error("name_token_account_or_zones_required");
  const query = "query ValidateZone($zoneTag: string, $filter: filter) { viewer { zones(filter: { zoneTag: $zoneTag }) { totals: httpRequestsAdaptiveGroups(limit: 1, filter: $filter) { count } } } }";
  const now = new Date();
  const then = new Date(now.getTime() - 60 * 60 * 1000);
  const filter = { datetime_geq: then.toISOString().replace(/\.\d{3}Z$/, "Z"), datetime_lt: now.toISOString().replace(/\.\d{3}Z$/, "Z"), requestSource: "eyeball" };
  for (const zoneTag of zoneIds) {
    const result = await cfGraphql(token, query, { zoneTag, filter });
    if (!result.data?.viewer?.zones?.length) throw new Error("zone_validation_failed");
  }
}

async function readAccounts(env) {
  const raw = await env.KV?.get(CONFIG_KEY);
  if (!raw) return [];
  const parsed = JSON.parse(raw);
  return Array.isArray(parsed) ? parsed.filter((account) => account?.ciphertext) : [];
}

async function decryptAccount(account, env) {
  const key = await deriveKey(env);
  const decrypted = await decryptJson(key, account.ciphertext);
  return {
    id: account.id,
    name: account.name,
    createdAt: account.createdAt,
    accountId: decrypted.accountId || "",
    zones: decrypted.zones,
    token: decrypted.token,
  };
}

async function decryptAccountsSafely(accounts, env) {
  const usable = [];
  const errors = [];
  for (const account of accounts || []) {
    try {
      usable.push(await decryptAccount(account, env));
    } catch (error) {
      errors.push({ id: account.id || "", name: account.name || "未命名账号", error: safeErrorMessage(error) });
    }
  }
  return { accounts: usable, errors };
}

function accountConfigErrorMessage(errors) {
  const names = (errors || []).map((item) => item.name || item.id).filter(Boolean).join("、") || "账号配置";
  return `无法读取已保存的账号配置：${names}。请确认 Pages 环境变量 ADMIN_USER / ADMIN_PASSWORD 与保存账号时一致；如果这是新 Pages 项目，请在后台删除旧账号后重新添加。`;
}

async function normalizeAccount(input, env) {
  const zones = Array.isArray(input.zones) ? input.zones : [];
  const normalizedZones = zones.map((zone) => ({ id: crypto.randomUUID(), zoneTag: String(zone.zoneTag || "").trim(), name: String(zone.name || "").trim() || "未命名区域" })).filter((zone) => zone.zoneTag);
  const accountId = String(input.accountId || "").trim();
  if (!input.name || !input.token || (!normalizedZones.length && !accountId)) throw new Error("name_token_account_or_zones_required");
  const id = crypto.randomUUID();
  const key = await deriveKey(env);
  const ciphertext = await encryptJson(key, { token: String(input.token).trim(), accountId, zones: normalizedZones });
  return {
    id,
    name: String(input.name).trim(),
    createdAt: beijingNow(),
    ciphertext,
  };
}

async function upsertAccount(accounts, input, env) {
  const incoming = await normalizeAccount(input, env);
  const key = await deriveKey(env);
  const incomingData = await decryptJson(key, incoming.ciphertext);
  const incomingTokenHash = await sha256(incomingData.token);
  const matches = [];

  for (let i = 0; i < accounts.length; i++) {
    const account = accounts[i];
    const data = await decryptJson(key, account.ciphertext);
    const sameAccountId = incomingData.accountId && data.accountId && incomingData.accountId === data.accountId;
    const sameToken = incomingTokenHash === await sha256(data.token || "");
    const existingZoneTags = new Set((data.zones || []).map((zone) => zone.zoneTag));
    const overlapsZone = (incomingData.zones || []).some((zone) => existingZoneTags.has(zone.zoneTag));
    if (sameAccountId || sameToken || overlapsZone) {
      matches.push({ index: i, account, data });
    }
  }

  if (!matches.length) return { accounts: [...accounts, incoming], account: await decryptAccount(incoming, env), action: "created", addedZones: incomingData.zones.length };

  const primary = matches[0];
  let mergedZones = { zones: primary.data.zones || [], added: 0 };
  for (const match of matches.slice(1)) mergedZones = mergeZones(mergedZones.zones, match.data.zones || []);
  const beforeIncomingCount = mergedZones.zones.length;
  mergedZones = mergeZones(mergedZones.zones, incomingData.zones || []);
  const mergedData = {
    token: incomingData.token || primary.data.token,
    accountId: incomingData.accountId || primary.data.accountId || "",
    zones: mergedZones.zones,
  };
  const mergedAccount = {
    ...primary.account,
    name: primary.account.name || incoming.name,
    ciphertext: await encryptJson(key, mergedData),
  };
  const duplicateIndexes = new Set(matches.map((match) => match.index));
  const nextAccounts = accounts.filter((_, index) => !duplicateIndexes.has(index));
  nextAccounts.push(mergedAccount);
  return { accounts: nextAccounts, account: await decryptAccount(mergedAccount, env), action: "merged", addedZones: mergedZones.zones.length - beforeIncomingCount, mergedDuplicates: matches.length };
}

function mergeZones(existing, incoming) {
  const zones = existing.map((zone) => ({ ...zone }));
  const byTag = new Map(zones.map((zone, index) => [zone.zoneTag, index]));
  let added = 0;
  for (const zone of incoming) {
    if (!byTag.has(zone.zoneTag)) {
      zones.push(zone);
      byTag.set(zone.zoneTag, zones.length - 1);
      added += 1;
      continue;
    }
    const old = zones[byTag.get(zone.zoneTag)];
    if ((!old.name || old.name === "未命名区域") && zone.name && zone.name !== "未命名区域") old.name = zone.name;
  }
  return { zones, added };
}

async function updateAccountLabels(accounts, input, env) {
  const id = String(input.id || "");
  const index = accounts.findIndex((account) => account.id === id);
  if (index === -1) throw new Error("account_not_found");
  const key = await deriveKey(env);
  const account = accounts[index];
  const data = await decryptJson(key, account.ciphertext);
  const zoneNames = new Map((input.zones || []).map((zone) => [String(zone.id || ""), String(zone.name || "").trim()]));
  data.zones = (data.zones || []).map((zone) => ({ ...zone, name: zoneNames.get(zone.id) || zone.name || "未命名区域" }));
  if (input.accountId !== undefined) data.accountId = String(input.accountId).trim();
  const updated = {
    ...account,
    name: String(input.name || "").trim() || account.name,
    ciphertext: await encryptJson(key, data),
  };
  const next = accounts.slice();
  next[index] = updated;
  return { accounts: next, account: await decryptAccount(updated, env) };
}

async function addAccountZones(accounts, input, env) {
  const id = String(input.id || "");
  const index = accounts.findIndex((account) => account.id === id);
  if (index === -1) throw new Error("account_not_found");
  const newZones = (input.zones || []).map((zone) => ({ id: crypto.randomUUID(), zoneTag: String(zone.zoneTag || "").trim(), name: String(zone.name || "").trim() || "未命名区域" })).filter((zone) => zone.zoneTag);
  if (!newZones.length) throw new Error("no_valid_zones");
  const key = await deriveKey(env);
  const account = accounts[index];
  const data = await decryptJson(key, account.ciphertext);
  const byTag = new Map((data.zones || []).map((z) => [z.zoneTag, z]));
  for (const zone of newZones) if (!byTag.has(zone.zoneTag)) { data.zones.push(zone); byTag.set(zone.zoneTag, zone); }
  const updated = { ...account, ciphertext: await encryptJson(key, data) };
  const next = accounts.slice();
  next[index] = updated;
  return { accounts: next, account: await decryptAccount(updated, env), addedZones: newZones.length };
}

async function removeAccountZone(accounts, accountId, zoneId, env) {
  const index = accounts.findIndex((account) => account.id === accountId);
  if (index === -1) throw new Error("account_not_found");
  const key = await deriveKey(env);
  const account = accounts[index];
  const data = await decryptJson(key, account.ciphertext);
  data.zones = (data.zones || []).filter((zone) => zone.id !== zoneId);
  const updated = { ...account, ciphertext: await encryptJson(key, data) };
  const next = accounts.slice();
  next[index] = updated;
  return { accounts: next, account: await decryptAccount(updated, env) };
}

async function deriveKey(env) {
  const material = `${env.ADMIN_USER || "admin"}:${env.ADMIN_PASSWORD || ""}`;
  const bytes = new TextEncoder().encode(material);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptJson(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return `${toB64(iv)}.${toB64(new Uint8Array(ciphertext))}`;
}

async function decryptJson(key, encoded) {
  const [ivPart, dataPart] = String(encoded || "").split(".");
  if (!ivPart || !dataPart) throw new Error("invalid_ciphertext");
  const iv = fromB64(ivPart);
  const data = fromB64(dataPart);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plaintext));
}

function toB64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromB64(text) {
  const padded = String(text).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(text).length + 3) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function readPrivacy(env) {
  const defaults = { publicTopIPs: false, publicTopHosts: false, publicTimeline: false, publicFilters: false, hideAiPanel: false, aiVerboseData: false };
  const raw = await env.KV?.get(PRIVACY_KEY);
  if (!raw) return defaults;
  return { ...defaults, ...normalizePrivacy(JSON.parse(raw)) };
}

async function writePrivacy(env, privacy) {
  if (!env.KV) throw new Error("missing_KV_binding");
  await env.KV.put(PRIVACY_KEY, JSON.stringify(privacy));
}

function normalizePrivacy(input) {
  return {
    publicTopIPs: Boolean(input.publicTopIPs),
    publicTopHosts: Boolean(input.publicTopHosts),
    publicTimeline: Boolean(input.publicTimeline),
    publicFilters: Boolean(input.publicFilters),
    hideAiPanel: Boolean(input.hideAiPanel),
    aiVerboseData: Boolean(input.aiVerboseData),
  };
}

function redactForPublic(body, privacy) {
  const safe = structuredClone(body);
  if (!privacy.publicTimeline) {
    safe.summary.timeline = [];
    if (safe.workerMetrics) safe.workerMetrics.timeline = [];
    if (safe.projectMetrics) safe.projectMetrics.timeline = [];
    for (const account of safe.accounts) {
      account.totals.timeline = [];
      for (const zone of account.zones || []) zone.timeline = [];
    }
  }
  if (!privacy.publicTopIPs) {
    safe.summary.topIPs = [];
    safe.summary.topCountries = [];
    for (const account of safe.accounts) {
      account.totals.topIPs = [];
      account.totals.topCountries = [];
      for (const zone of account.zones || []) {
        zone.topIPs = [];
        zone.topCountries = [];
      }
    }
  }
  if (!privacy.publicTopHosts) {
    safe.summary.topHosts = [];
    for (const account of safe.accounts) {
      account.totals.topHosts = [];
      for (const zone of account.zones || []) zone.topHosts = [];
    }
  }
  if (!privacy.publicFilters) {
    safe.accounts = safe.accounts.map((account) => ({ id: account.id, name: account.name, totals: { totalRequests: account.totals.totalRequests, totalBytes: account.totals.totalBytes } }));
    safe.host = "";
    if (safe.workerMetrics) safe.workerMetrics.accounts = [];
    if (safe.projectMetrics) safe.projectMetrics.accounts = [];
  }
  return safe;
}

async function writeAccounts(env, accounts) {
  if (!env.KV) throw new Error("missing_KV_binding");
  await env.KV.put(CONFIG_KEY, JSON.stringify(accounts));
}

function publicAccount(account) {
  return { id: account.id, name: account.name, createdAt: displayTime(account.createdAt), hasAccountId: Boolean(account.accountId), zones: (account.zones || []).map((zone) => ({ id: zone.id, name: zone.name || "未命名区域" })) };
}

function displayTime(value) {
  if (!value) return "";
  if (/GMT\+8$/.test(String(value))) return String(value);
  return formatBeijingTime(value);
}

function stripSecrets(account) {
  return {
    id: account.id,
    name: account.name,
    zones: (account.zones || []).map((zone) => ({ id: zone.id, name: zone.name || "未命名区域" })),
    totals: account.totals,
  };
}

function parseHours(value) {
  const hours = Number(value || 24);
  return RANGE_HOURS.has(hours) ? hours : 24;
}

function cleanHost(host) {
  return String(host || "").trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
}

function cleanProjectName(value) {
  return String(value || "").trim().replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 128);
}

function timeRange(hours) {
  const end = new Date();
  const start = new Date(end.getTime() - hours * 60 * 60 * 1000);
  return { start: start.toISOString().replace(/\.\d{3}Z$/, "Z"), end: end.toISOString().replace(/\.\d{3}Z$/, "Z") };
}

function floorTime(ms, stepMs) {
  return Math.floor(ms / stepMs) * stepMs;
}

async function isAdmin(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.match(/(?:^|; )cfra_session=([^;]+)/)?.[1];
  if (!token) return false;
  return token === await signSession(request, env);
}

async function signSession(request, env) {
  const ua = request.headers.get("User-Agent") || "";
  const password = env.ADMIN_PASSWORD || "";
  const user = env.ADMIN_USER || "admin";
  const day = Math.floor(Date.now() / 86400000);
  return sha256(`${user}:${password}:${ua}:${day}`);
}

async function sha256(value) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(hash)].map((n) => n.toString(16).padStart(2, "0")).join("");
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", ...headers } });
}

function html(body) {
  return new Response(body, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function setupRequiredPage(missing = ["ADMIN_PASSWORD"]) {
  const items = missing.map((name) => `<li><a href="https://github.com/PoemMisty/CF-Request-Analytics-Panel" target="_blank" rel="noopener"><code>${name}</code></a></li>`).join("");
  const html = SETUP_REQUIRED_HTML.replace("{{MISSING_ITEMS}}", items);
  return new Response(html, {
    status: 503,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function getMissingBindings(env) {
  const missing = [];
  if (!env.KV || typeof env.KV.get !== "function" || typeof env.KV.put !== "function") missing.push("KV");
  return missing;
}

function text(body) {
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { Location: location } });
}

const SETUP_REQUIRED_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>需要完成配置</title>
  <style>
    * { box-sizing:border-box; min-width:0; }
    html, body { max-width:100%; overflow-x:hidden; }
    body { margin:0; min-height:100vh; display:grid; place-items:center; padding:22px clamp(14px,4vw,44px); background:#0a1020; color:#eef5ff; font-family:Inter,"PingFang SC","Microsoft YaHei",Arial,sans-serif; }
    .card { width:min(560px,100%); background:#111a2f; border:1px solid #2a3a5d; border-radius:24px; padding:28px; box-shadow:0 24px 70px rgba(0,0,0,.28); }
    h1 { margin:0 0 12px; font-size:clamp(24px,5vw,34px); }
    p, li { color:#8ea3c3; line-height:1.7; }
    a { color:#5eead4; text-decoration:none; }
    a:hover { text-decoration:underline; }
    ul { margin:14px 0; padding-left:22px; }
    code { display:inline-block; margin:2px 0; padding:3px 7px; border-radius:8px; background:#0d172b; color:#5eead4; overflow-wrap:anywhere; }
  </style>
</head>
<body>
  <main class="card">
    <h1>需要完成配置</h1>
    <p>当前项目缺少必要配置，页面无法打开。请根据<a href="https://github.com/PoemMisty/CF-Request-Analytics-Panel" target="_blank" rel="noopener">仓库 README 文档</a>补齐以下配置：</p>
    <ul>{{MISSING_ITEMS}}</ul>
    <p>如果缺少 <a href="https://github.com/PoemMisty/CF-Request-Analytics-Panel" target="_blank" rel="noopener"><code>ADMIN_PASSWORD</code></a>，请在 Cloudflare Pages 环境变量中添加管理员密码。如果缺少 <a href="https://github.com/PoemMisty/CF-Request-Analytics-Panel" target="_blank" rel="noopener"><code>KV</code></a> 或 <a href="https://github.com/PoemMisty/CF-Request-Analytics-Panel" target="_blank" rel="noopener"><code>AI</code></a>，请在 Pages 项目的 Functions 设置中完成对应绑定。</p>
    <p>保存配置后重新部署 Pages，再重新访问本页面。</p>
  </main>
</body>
</html>`;

const INDEX_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CF Request Analytics Panel</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap/dist/css/jsvectormap.min.css">
  <script src="https://cdn.jsdelivr.net/npm/jsvectormap"></script>
  <script src="https://cdn.jsdelivr.net/npm/jsvectormap/dist/maps/world-merc.js"></script>
  <style>
    :root { color-scheme: dark; --bg:#0a1020; --panel:#111a2f; --card:#16213a; --text:#eef5ff; --muted:#8ea3c3; --line:#2a3a5d; --accent:#5eead4; --warn:#f59e0b; --bad:#fb7185; }
    * { box-sizing: border-box; min-width:0; }
    html, body { max-width:100%; overflow-x:hidden; }
    body { margin:0; font-family: Inter, "PingFang SC", "Microsoft YaHei", Arial, sans-serif; color:var(--text); background: radial-gradient(circle at top left, rgba(94,234,212,.18), transparent 32%), linear-gradient(135deg,#070b16,#0a1020 60%,#10182c); min-height:100vh; }
    header { padding:24px clamp(14px,4vw,44px); display:flex; align-items:center; justify-content:space-between; gap:18px; border-bottom:1px solid rgba(255,255,255,.08); }
    h1 { margin:0; font-size:clamp(24px,4vw,42px); letter-spacing:-.04em; }
    main { padding:22px clamp(14px,4vw,44px) 24px; display:grid; gap:18px; }
    footer { padding:0 clamp(14px,4vw,44px) 34px; color:var(--muted); text-align:center; font-size:13px; }
    footer a { color:var(--accent); text-decoration:none; }
    footer a:hover { text-decoration:underline; }
    .github-link { width:42px; height:42px; display:inline-grid; place-items:center; border:1px solid var(--line); border-radius:14px; color:var(--text); text-decoration:none; background:rgba(255,255,255,.04); transition:transform .18s ease,border-color .18s ease,background .18s ease; }
    .github-link:hover { transform:translateY(-1px); border-color:var(--accent); background:rgba(94,234,212,.08); }
    .github-link svg { width:22px; height:22px; fill:currentColor; }
    .top-action { display:inline-flex; align-items:center; justify-content:center; background:#243655; color:var(--text); border:1px solid var(--line); text-decoration:none; border-radius:13px; padding:11px 14px; font:inherit; font-weight:800; line-height:normal; }
    button, input, select, textarea { font:inherit; }
    button { min-width:256px; border:0; border-radius:14px; padding:11px 15px; color:#07101d; background:var(--accent); font-weight:800; cursor:pointer; }
    button.secondary { background:#243655; color:var(--text); border:1px solid var(--line); }
    button.danger { background:var(--bad); color:#1b0710; }
    button[hidden] { display:none; }
    input, select, textarea { width:100%; border:1px solid var(--line); border-radius:14px; color:var(--text); background:#0d172b; padding:12px 13px; }
    select { appearance:none; padding-right:42px; background-image:linear-gradient(45deg, transparent 50%, var(--muted) 50%), linear-gradient(135deg, var(--muted) 50%, transparent 50%); background-position:calc(100% - 19px) 52%, calc(100% - 13px) 52%; background-size:6px 6px, 6px 6px; background-repeat:no-repeat; }
    .grid { display:grid; gap:16px; }
    .toolbar { grid-template-columns: repeat(5, minmax(0,1fr)); align-items:end; }
    .toolbar button { grid-column:1 / -1; justify-self:end; }
    .cards { grid-template-columns: repeat(3, minmax(0,1fr)); }
    .panel { border:1px solid rgba(255,255,255,.09); background:rgba(17,26,47,.84); border-radius:24px; padding:20px; box-shadow:0 24px 70px rgba(0,0,0,.28); overflow:hidden; }
    #chartPanel, #trafficChartPanel { min-height:300px; }
    .chart-wrap { position:relative; height:clamp(260px, 32vh, 420px); width:100%; }
    .chart-wrap canvas { width:100% !important; height:100% !important; display:block; }
    .chart-head { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:12px; }
    .chart-head label { min-width:220px; }
    .country-map { overflow:hidden; min-height:auto; border:1px solid rgba(255,255,255,.08); border-radius:18px; background:radial-gradient(circle at 50% 45%, rgba(94,234,212,.12), transparent 55%), rgba(255,255,255,.03); padding:8px; }
    #worldMap { width:100%; height:clamp(280px, 36vw, 460px); min-height:280px; }
    .jvm-container { background:transparent !important; }
    .jvm-region { stroke:rgba(148,163,184,.42); stroke-width:.65; }
    .jvm-tooltip { background:#0d172b; border:1px solid var(--line); color:var(--text); border-radius:10px; padding:7px 9px; box-shadow:0 18px 45px rgba(0,0,0,.35); }
    .map-legend { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; color:var(--muted); font-size:12px; }
    .map-legend span { display:inline-flex; align-items:center; gap:5px; }
    .map-legend i { width:10px; height:10px; border-radius:999px; display:inline-block; }
    .country-table { margin-top:12px; }
    .country-table col:nth-child(1) { width:54%; }
    .country-table col:nth-child(2) { width:26%; }
    .country-table col:nth-child(3) { width:20%; }
    .country-table th:nth-child(3), .country-table td:nth-child(3) { white-space:nowrap; }
    label { display:grid; gap:8px; }
    .card small, label, .muted { color:var(--muted); }
    .split { display:grid; grid-template-columns: 1.45fr .95fr; gap:16px; }
    table { width:100%; border-collapse:collapse; table-layout:fixed; }
    th, td { padding:11px 8px; border-bottom:1px solid rgba(255,255,255,.08); text-align:left; overflow-wrap:anywhere; word-break:break-word; }
    th { color:var(--muted); font-weight:600; }
    th { white-space:nowrap; word-break:keep-all; overflow-wrap:normal; }
    .ip-table col:nth-child(1) { width:48%; }
    .ip-table col:nth-child(2) { width:14%; }
    .ip-table col:nth-child(3) { width:22%; }
    .ip-table col:nth-child(4) { width:16%; }
    .host-table col:nth-child(1) { width:58%; }
    .host-table col:nth-child(2) { width:24%; }
    .host-table col:nth-child(3) { width:18%; }
    .ip-table th:nth-child(4), .ip-table td:nth-child(4), .host-table th:nth-child(3), .host-table td:nth-child(3) { white-space:nowrap; }
    .login { max-width:380px; margin:auto; margin-top:8vh; }
    .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:flex-end; }
    header > .row { margin-left:auto; justify-content:flex-end; }
    header > .row { margin-left:auto; justify-content:flex-end; }
    .notice { white-space:pre-wrap; line-height:1.7; color:#dbeafe; }
    .notice h3 { margin:16px 0 6px; color:var(--text); }
    .notice ul { margin:6px 0 10px; padding-left:20px; }
    .notice li { margin:4px 0; }
    .blocked { opacity:.55; pointer-events:none; }
    .usage-bars { grid-template-columns:repeat(3,minmax(0,1fr)); }
    .usage-card { background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08); border-radius:18px; padding:16px; }
    .usage-card .top { display:flex; justify-content:space-between; gap:10px; color:var(--muted); margin-bottom:10px; }
    .bar { height:12px; border-radius:99px; background:rgba(255,255,255,.08); overflow:hidden; }
    .bar span { display:block; height:100%; width:0; border-radius:99px; background:linear-gradient(90deg,#22c55e,#eab308,#ef4444); transition:width .5s ease; }
    .usage-card strong { display:block; margin-top:10px; font-size:20px; }
    .usage-card strong { white-space:nowrap; }
    .modal-mask { position:fixed; inset:0; background:rgba(3,7,18,.72); display:none; place-items:center; z-index:50; padding:18px; }
    .modal-mask.open { display:grid; }
    .modal-card { width:min(460px,100%); border:1px solid var(--line); background:#111a2f; border-radius:24px; padding:22px; box-shadow:0 30px 90px rgba(0,0,0,.45); }
    .modal-card code { display:block; margin:12px 0; padding:12px; border-radius:14px; background:#0d172b; color:var(--accent); overflow-wrap:anywhere; }
    .admin-only { display:none !important; }
    body.admin .admin-only { display:revert !important; }
    body.admin .top-action.admin-only { display:inline-flex !important; }
    .privacy-hidden { display:none !important; }
    .overlay-panel { display:none; }
    .overlay-panel.open { display:grid; }
    @media (max-width: 900px) { .toolbar, .cards, .split { grid-template-columns:1fr; } header { align-items:flex-start; flex-direction:column; } header > .row { margin-left:0; justify-content:flex-start; } }
    @media (max-width: 900px) { .usage-bars { grid-template-columns:1fr; } }
    @media (max-width: 520px) { h1{font-size:28px}.panel{padding:14px;border-radius:18px}.usage-card{padding:14px}.usage-card strong{font-size:20px}.row a,.row button,button{width:100%;justify-content:center;text-align:center}.toolbar button{justify-self:stretch}.cards{gap:10px}#worldMap{height:clamp(240px,70vw,340px);min-height:240px}.map-legend{margin-top:4px} th,td{padding:10px 6px;font-size:13px}.ip-table col:nth-child(1){width:50%}.ip-table col:nth-child(2){width:12%}.ip-table col:nth-child(3){width:20%}.ip-table col:nth-child(4){width:18%}.host-table col:nth-child(1){width:58%}.host-table col:nth-child(2){width:23%}.host-table col:nth-child(3){width:19%} }
    @media (max-width: 900px) and (orientation: landscape) { #worldMap{height:clamp(220px,48vh,320px);min-height:220px} }
  </style>
</head>
<body>
  <header>
    <div><h1>CF Request Analytics</h1><div class="muted">多账号 HTTP 请求分析、Top IP、趋势折线与 Workers AI 风险判断</div></div>
    <div class="row"><a class="github-link" href="https://github.com/PoemMisty/CF-Request-Analytics-Panel" target="_blank" rel="noopener" aria-label="GitHub"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 .5a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.03c-3.34.73-4.04-1.61-4.04-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.09-.75.08-.73.08-.73 1.2.08 1.84 1.24 1.84 1.24 1.07 1.83 2.81 1.3 3.5.99.11-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23A11.45 11.45 0 0 1 12 5.8c1.02 0 2.04.14 3 .4 2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.81 5.63-5.49 5.93.43.37.82 1.1.82 2.22v3.29c0 .32.22.7.83.58A12 12 0 0 0 12 .5Z"/></svg></a><a id="loginEntry" href="/login" class="top-action">管理员登录</a><a id="adminEntry" href="/admin" class="admin-only top-action">后台管理</a></div>
  </header>
  <main>
    <section class="panel grid toolbar">
      <label id="accountFilter">账号<select id="accountSelect"><option value="all">全部账号汇总</option></select></label>
      <label id="zoneFilter">区域<select id="zoneSelect"><option value="all">全部区域汇总</option></select></label>
      <label id="hostFilter">主机名<input id="hostInput" placeholder="可选：输入要筛选的主机名"></label>
      <label id="projectFilter">服务名 / 项目名<input id="projectInput" placeholder="可选：输入可观测性中的 Service 名称"></label>
      <label>时间范围<select id="rangeSelect"><option value="24">过去 24 小时</option><option value="12">过去 12 小时</option><option value="6">过去 6 小时</option><option value="1">过去 1 小时</option></select></label>
      <button id="refreshBtn">应用筛选</button>
    </section>
    <section class="panel" id="aiPanel">
      <div class="row" style="justify-content:space-between"><h3>AI 分析</h3><button id="aiBtn" class="admin-only">AI 分析 24h</button></div>
      <div id="aiResult" class="notice muted">管理员登录后可基于当前筛选域名的 24 小时数据分析异常盗用、自动探测或正常波动。</div>
      <div id="analysisBlocked" class="notice muted privacy-hidden">当前账号未配置区域 ID，只能显示 Workers/Pages 用量进度，无法展示域名请求明细或 AI 分析。</div>
    </section>
    <section class="panel grid cards">
      <div class="usage-card"><div class="top"><span>总请求数</span></div><strong id="totalRequests">-</strong><small id="requestScopeText">-</small></div>
      <div class="usage-card"><div class="top"><span>边缘响应流量</span></div><strong id="totalBytes">-</strong><small id="trafficScopeText">-</small></div>
      <div class="usage-card"><div class="top"><span>当前时间范围</span></div><strong id="rangeText">-</strong><small>北京时间 GMT+8</small></div>
    </section>
    <section class="panel grid usage-bars">
      <div class="usage-card"><div class="top"><span>Workers 请求</span><span id="workersPct">-</span></div><div class="bar"><span id="workersBar"></span></div><strong id="workersUsage">-</strong><small id="workersScopeText">-</small></div>
      <div class="usage-card"><div class="top"><span>Pages 请求</span><span id="pagesPct">-</span></div><div class="bar"><span id="pagesBar"></span></div><strong id="pagesUsage">-</strong><small id="pagesScopeText">-</small></div>
      <div class="usage-card"><div class="top"><span>共享额度总请求</span><span id="totalUsagePct">-</span></div><div class="bar"><span id="totalUsageBar"></span></div><strong id="totalUsage">-</strong><small>Workers + Pages 合计</small></div>
      <div id="usageNote" class="muted" style="grid-column:1/-1;white-space:pre-wrap"></div>
    </section>
    <section class="panel" id="chartPanel">
      <div class="chart-head"><h3 id="requestChartTitle">请求数折线</h3><label>数据源<select id="requestChartSource"><option value="http">HTTP 请求</option><option value="worker">Worker 请求</option></select></label></div>
      <div class="chart-wrap"><canvas id="lineChart"></canvas></div>
      <div id="requestChartNote" class="muted"></div>
      <div id="chartBlocked" class="muted privacy-hidden">折线图涉及访问时间分布，管理员未开放未登录展示。</div>
    </section>
    <section class="panel" id="trafficChartPanel">
      <div class="chart-head"><h3 id="trafficChartTitle">流量折线</h3></div>
      <div class="chart-wrap"><canvas id="trafficChart"></canvas></div>
      <div id="trafficChartBlocked" class="muted privacy-hidden">流量折线涉及访问时间分布，管理员未开放未登录展示。</div>
    </section>
    <section class="panel" id="countryPanel">
      <div class="chart-head"><h3>国家/地区请求地图</h3></div>
      <div id="countryMap" class="country-map"></div>
      <div id="countryBlocked" class="muted privacy-hidden">国家/地区分布涉及访问来源，管理员未开放未登录展示。</div>
    </section>
    <section class="split">
      <div class="panel"><h3>Top IPs</h3><div id="ipBlocked" class="muted privacy-hidden">详细 IP 涉及隐私，管理员未开放未登录展示。</div><table id="ipTableWrap" class="ip-table"><colgroup><col><col><col><col></colgroup><thead><tr><th>IP</th><th>国家</th><th>请求</th><th>占比</th></tr></thead><tbody id="ipTable"></tbody></table></div>
      <div class="panel"><h3>Top Hosts</h3><div id="hostBlocked" class="muted privacy-hidden">主机明细涉及隐私，管理员未开放未登录展示。</div><table id="hostTableWrap" class="host-table"><colgroup><col><col><col></colgroup><thead><tr><th>Host</th><th>请求</th><th>占比</th></tr></thead><tbody id="hostTable"></tbody></table></div>
    </section>
  </main>
  <footer>Powered by <a href="https://github.com/PoemMisty/CF-Request-Analytics-Panel" target="_blank" rel="noopener">CF Request Analytics Panel</a></footer>
  <div id="aiConfirmMask" class="modal-mask">
    <div class="modal-card">
      <h3>确认分析域名</h3>
      <p class="muted">AI 盗用风险分析会基于当前账号、区域、域名和服务名的筛选数据。请确认该域名位于此账号下，当前区域 ID 已绑定/对应这个域名，并且服务名与 Cloudflare 可观测性中的 Service 一致，否则无法正确分析。</p>
      <small>当前账号</small><code id="aiConfirmAccount"></code>
      <small>当前区域</small><code id="aiConfirmZone"></code>
      <small>当前域名</small><code id="aiConfirmHost"></code>
      <small>当前服务名 / 项目名</small><code id="aiConfirmProject"></code>
      <div class="row"><button id="aiConfirmYes" type="button">确认并分析</button><button id="aiConfirmNo" class="secondary" type="button">取消</button></div>
    </div>
  </div>
  <script>
    const $ = (id) => document.getElementById(id);
    let chart;
    let trafficChart;
    let currentSummary = emptyDashboardSummary();
    let currentProjectMetrics = null;
    let currentWorkerMetrics = null;
    let currentAvailable = true;
    let accountCache = [];
    let pendingAiHost = "";
    const NO_ACCOUNT_MESSAGE = "当前还没有账号配置。请先登录后台添加 Cloudflare 账号后再查看分析或使用 AI 分析。";
    let session = { admin: false, aiAvailable: false, privacy: { publicTopIPs: false, publicTopHosts: false, publicTimeline: false, publicFilters: false, hideAiPanel: false } };
    async function api(path, options = {}) {
      const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
      const contentType = res.headers.get("content-type") || "";
      const data = contentType.includes("application/json") ? await res.json() : { error: "服务端返回非 JSON 响应，请检查 Pages Functions 日志。" };
      if (!res.ok) { const err = new Error(data.message || data.error || "请求失败"); err.code = data.error || "request_failed"; throw err; }
      return data;
    }
    function fmt(n) { const value = Number(n || 0); const abs = Math.abs(value); if (abs < 1000) return Intl.NumberFormat("zh-CN").format(value); const units = [[1e12,"T"],[1e9,"B"],[1e6,"M"],[1e3,"K"]]; const [base, suffix] = units.find(([size]) => abs >= size); const scaled = value / base; const fixed = Math.abs(scaled) >= 100 ? 0 : Math.abs(scaled) >= 10 ? 1 : 2; return Number(scaled.toFixed(fixed)).toString() + suffix; }
    function bytes(n) { if (!n) return "0 B"; const units=["B","KB","MB","GB","TB"]; let i=0,v=n; while(v>=1024&&i<units.length-1){v/=1024;i++;} return v.toFixed(i?2:0)+" "+units[i]; }
    function chartBytes(n) { if (!n) return "0 B"; const units=["B","KB","MB","GB","TB"]; let i=0,v=Math.abs(Number(n)||0); while(v>=999.5&&i<units.length-1){v/=1024;i++;} const fixed = v >= 100 ? 0 : v >= 10 ? 1 : 2; return (n < 0 ? "-" : "") + v.toFixed(fixed).replace(/\.0+$/, "").replace(/(\.\d*[1-9])0+$/, "$1") + " " + units[i]; }
    async function init() { session = await api("/api/session"); document.body.classList.toggle("admin", session.admin); $("loginEntry").classList.toggle("privacy-hidden", session.admin); applyPrivacy(session.privacy); if (session.admin) await loadAccounts(); await refresh(); }
    function applyPrivacy(privacy) { const canFilter = session.admin || privacy.publicFilters; const canTimeline = session.admin || privacy.publicTimeline; const canTopIPs = session.admin || privacy.publicTopIPs; const canTopHosts = session.admin || privacy.publicTopHosts; $("aiPanel").classList.toggle("privacy-hidden", Boolean(privacy.hideAiPanel)); $("accountFilter").classList.toggle("privacy-hidden", !canFilter); $("zoneFilter").classList.toggle("privacy-hidden", !canFilter); $("hostFilter").classList.toggle("privacy-hidden", !canFilter); $("projectFilter").classList.toggle("privacy-hidden", !canFilter); $("chartBlocked").classList.toggle("privacy-hidden", canTimeline); $("trafficChartBlocked").classList.toggle("privacy-hidden", canTimeline); $("lineChart").classList.toggle("privacy-hidden", !canTimeline); $("trafficChart").classList.toggle("privacy-hidden", !canTimeline); $("ipBlocked").classList.toggle("privacy-hidden", canTopIPs); $("countryBlocked").classList.toggle("privacy-hidden", canTopIPs); $("ipTableWrap").classList.toggle("privacy-hidden", !canTopIPs); $("countryMap").classList.toggle("privacy-hidden", !canTopIPs); $("hostBlocked").classList.toggle("privacy-hidden", canTopHosts); $("hostTableWrap").classList.toggle("privacy-hidden", !canTopHosts); }
    function escapeHtml(value) { return String(value || "").replace(/[&<>"]/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[ch])); }
    function inlineMarkdown(value) { return escapeHtml(value).replace(new RegExp("\\\\*\\\\*([^*]+)\\\\*\\\\*", "g"), "<strong>$1</strong>"); }
    function renderMarkdown(text) { const lines = String(text || "").split(String.fromCharCode(10)); let html = ""; let list = ""; const closeList = () => { if (list) { html += "</" + list + ">"; list = ""; } }; const sectionTitle = /^(结论|风险等级|依据|可能原因|建议|完整数据)$/; for (const raw of lines) { const line = raw.trim(); if (!line) { closeList(); continue; } if (line.startsWith("#### ")) { closeList(); html += "<h4>" + inlineMarkdown(line.slice(5)) + "</h4>"; continue; } if (line.startsWith("### ")) { closeList(); html += "<h3>" + inlineMarkdown(line.slice(4)) + "</h3>"; continue; } if (sectionTitle.test(line)) { closeList(); html += "<h3>" + inlineMarkdown(line) + "</h3>"; continue; } const ordered = line.match(/^\d+[.、]\s*(.+)$/); if (ordered) { if (list !== "ol") { closeList(); html += "<ol>"; list = "ol"; } html += "<li>" + inlineMarkdown(ordered[1]) + "</li>"; continue; } if (line.startsWith("- ")) { if (list !== "ul") { closeList(); html += "<ul>"; list = "ul"; } html += "<li>" + inlineMarkdown(line.slice(2)) + "</li>"; continue; } closeList(); html += "<p>" + inlineMarkdown(line) + "</p>"; } closeList(); return html; }
    async function loadAccounts() { const data = await api("/api/accounts").catch(() => ({accounts:[]})); accountCache = data.accounts || []; $("accountSelect").innerHTML = '<option value="all">全部账号汇总</option>' + accountCache.map(a => '<option value="' + escapeHtml(a.id) + '">' + escapeHtml(a.name) + '</option>').join(""); loadZones(); }
    function loadZones() { const accountId = $("accountSelect").value; const accounts = accountId === "all" ? accountCache : accountCache.filter(a => a.id === accountId); const zones = accounts.flatMap(a => (a.zones || []).map(z => ({ id:z.id, name:(accountId === "all" ? a.name + " / " : "") + (z.name || "未命名区域") }))); $("zoneSelect").innerHTML = '<option value="all">全部区域汇总</option>' + zones.map(z => '<option value="' + escapeHtml(z.id) + '">' + escapeHtml(z.name) + '</option>').join(""); }
    function emptyDashboardSummary() { return { totalRequests:0, totalBytes:0, timeline:[], topIPs:[], topHosts:[], topCountries:[] }; }
    function selectedScopeText() { const account = $("accountSelect").options[$("accountSelect").selectedIndex]?.textContent || "全部账号汇总"; const zone = $("zoneSelect").options[$("zoneSelect").selectedIndex]?.textContent || "全部区域汇总"; return account + " / " + zone; }
    async function refresh() { const q = new URLSearchParams({ account: $("accountSelect").value, zone: $("zoneSelect").value, hours: $("rangeSelect").value, host: $("hostInput").value.trim(), projectName: $("projectInput").value.trim() }); try { const data = await api("/api/analytics?" + q); render(data.summary, data.hours, data.usage, data.analyticsAvailable !== false, data.projectMetrics, data.workerMetrics); } catch (err) { if (err.code === "no_account") { render(emptyDashboardSummary(), $("rangeSelect").value, { workers:0, pages:0, total:0, limit:0 }, false, null, null); $("analysisBlocked").textContent = err.message; return; } throw err; } }
    function shortBeijingTime(value) { const text = String(value || "").replace("T", " "); const match = text.match(/^(?:[0-9]{4}-)?([0-9]{2}-[0-9]{2})[ ]+([0-9]{2}:[0-9]{2})/); return match ? match[1] + " " + match[2] : text.replace(/^[0-9]{4}-/, "").replace(/:[0-9]{2}(?:[ ]+GMT[+]8|Z)?$/, ""); }
    function percentText(count, total) { if (!total) return "0.0%"; const pct = count / total * 100; return pct < 0.1 ? "＜0.1%" : pct.toFixed(pct >= 10 ? 0 : 1) + "%"; }
    const countryCodeMap = {"中国":"CN","China":"CN","中国香港":"HK","Hong Kong":"HK","台湾":"TW","Taiwan":"TW","日本":"JP","Japan":"JP","韩国":"KR","South Korea":"KR","新加坡":"SG","Singapore":"SG","印度":"IN","India":"IN","俄罗斯":"RU","Russia":"RU","美国":"US","United States":"US","加拿大":"CA","Canada":"CA","巴西":"BR","Brazil":"BR","英国":"GB","United Kingdom":"GB","德国":"DE","Germany":"DE","法国":"FR","France":"FR","荷兰":"NL","Netherlands":"NL","意大利":"IT","Italy":"IT","西班牙":"ES","Spain":"ES","澳大利亚":"AU","Australia":"AU","印度尼西亚":"ID","Indonesia":"ID","泰国":"TH","Thailand":"TH","越南":"VN","Vietnam":"VN","菲律宾":"PH","Philippines":"PH","马来西亚":"MY","Malaysia":"MY","土耳其":"TR","Turkey":"TR","阿联酋":"AE","United Arab Emirates":"AE","南非":"ZA","South Africa":"ZA","日本":"JP","韩国":"KR","中国澳门":"MO","Macao":"MO","葡萄牙":"PT","Portugal":"PT","瑞士":"CH","Switzerland":"CH","瑞典":"SE","Sweden":"SE","挪威":"NO","Norway":"NO","芬兰":"FI","Finland":"FI","丹麦":"DK","Denmark":"DK","波兰":"PL","Poland":"PL","捷克":"CZ","Czech Republic":"CZ","奥地利":"AT","Austria":"AT","比利时":"BE","Belgium":"BE","爱尔兰":"IE","Ireland":"IE","墨西哥":"MX","Mexico":"MX","智利":"CL","Chile":"CL","阿根廷":"AR","Argentina":"AR","哥伦比亚":"CO","Colombia":"CO","秘鲁":"PE","Peru":"PE","沙特阿拉伯":"SA","Saudi Arabia":"SA","以色列":"IL","Israel":"IL","巴基斯坦":"PK","Pakistan":"PK","孟加拉国":"BD","Bangladesh":"BD","尼泊尔":"NP","Nepal":"NP","斯里兰卡":"LK","Sri Lanka":"LK"};
    let worldMapInstance = null;
    let worldMapReady = false;
    let worldMapLabels = {};
    let worldMapColoredCodes = [];
    function countryColor(pct) { if (pct >= 50) return "rgba(94,234,212,1)"; if (pct >= 30) return "rgba(94,234,212,.82)"; if (pct >= 20) return "rgba(94,234,212,.66)"; if (pct >= 10) return "rgba(94,234,212,.5)"; if (pct >= 5) return "rgba(94,234,212,.34)"; if (pct >= 0.1) return "rgba(94,234,212,.22)"; return "rgba(94,234,212,.12)"; }
    function applyCountryColors(values, total) { if (!worldMapInstance?.regions) return; for (const code of worldMapColoredCodes) { if (worldMapInstance.regions[code]) worldMapInstance.regions[code].element.setStyle("fill", "rgba(219,234,254,.16)"); } worldMapColoredCodes = []; for (const [code, count] of Object.entries(values)) { if (!worldMapInstance.regions[code]) continue; worldMapInstance.regions[code].element.setStyle("fill", countryColor(Number(count || 0) / Math.max(Number(total || 0), 1) * 100)); worldMapColoredCodes.push(code); } }
    function attachMapWheelZoom() { const el = $("worldMap"); if (!el || el.dataset.ctrlZoomBound === "1") return; el.dataset.ctrlZoomBound = "1"; el.addEventListener("wheel", (event) => { if (!event.ctrlKey || !worldMapInstance?._setScale) return; event.preventDefault(); const rect = el.getBoundingClientRect(); const x = event.clientX - rect.left; const y = event.clientY - rect.top; const factor = event.deltaY < 0 ? 1.25 : 0.8; worldMapInstance._setScale(worldMapInstance.scale * factor, x, y, false, worldMapInstance.params?.zoomAnimate); }, { passive: false }); }
    function countryCode(name) { const code = String(name || "").trim().toUpperCase(); if (/^[A-Z]{2}$/.test(code)) return code; return countryCodeMap[name] || ""; }
    function countryListHtml(list, total) { return '<table class="country-table"><colgroup><col><col><col></colgroup><thead><tr><th>国家</th><th>请求</th><th>占比</th></tr></thead><tbody>' + list.slice(0, 12).map((item) => { const name = item.dimensions.clientCountryName || "未知"; const count = Number(item.count || 0); return '<tr><td>' + escapeHtml(name) + '</td><td>' + fmt(count) + '</td><td>' + percentText(count, total) + '</td></tr>'; }).join("") + '</tbody></table>'; }
    function renderCountryMap(items, total) { try { const list = (items || []).filter((item) => item?.dimensions?.clientCountryName).sort((a, b) => Number(b.count || 0) - Number(a.count || 0)).slice(0, 40); if (!list.length || !total) { $("countryMap").innerHTML = '<div class="muted" style="padding:6px 12px">暂无国家/地区分布数据</div>'; return; } const values = {}; const labels = {}; for (const item of list) { const name = item.dimensions.clientCountryName || "未知"; const code = countryCode(name); if (!code) continue; const count = Number(item.count || 0); values[code] = count; labels[code] = name + '：' + fmt(count) + '（' + percentText(count, total) + '）'; } const details = countryListHtml(list, total); if (!Object.keys(values).length) { $("countryMap").innerHTML = '<div class="muted" style="padding:6px 12px">暂无可映射到世界地图的国家数据</div>' + details; return; } if (typeof jsVectorMap !== "function") { $("countryMap").innerHTML = '<div class="muted" style="padding:6px 12px">世界地图资源加载失败，请刷新重试。</div>' + details; return; } worldMapLabels = labels; if (!worldMapInstance) { $("countryMap").innerHTML = '<div id="worldMap"></div><div class="map-legend"><span><i style="background:rgba(94,234,212,.22)"></i>0.1%+</span><span><i style="background:rgba(94,234,212,.34)"></i>5%+</span><span><i style="background:rgba(94,234,212,.5)"></i>10%+</span><span><i style="background:rgba(94,234,212,.66)"></i>20%+</span><span><i style="background:rgba(94,234,212,.82)"></i>30%+</span><span><i style="background:rgba(94,234,212,1)"></i>50%+</span></div><div id="countryRank"></div>'; worldMapInstance = new jsVectorMap({ selector: "#worldMap", map: "world_merc", backgroundColor: "transparent", zoomButtons: false, zoomOnScroll: false, regionStyle: { initial: { fill: "rgba(219,234,254,.16)", stroke: "rgba(148,163,184,.42)", strokeWidth: 0.65 }, hover: { stroke: "#5eead4", strokeWidth: 1.2 }, selected: { stroke: "#5eead4", strokeWidth: 1.2 } }, onRegionTooltipShow: (event, tooltip, code) => { if (worldMapLabels[code]) tooltip.text(worldMapLabels[code]); } }); attachMapWheelZoom(); $("countryRank").innerHTML = details; worldMapReady = true; setTimeout(() => { if (worldMapInstance) { worldMapInstance.updateSize(); applyCountryColors(values, total); } }, 60); return; } if (worldMapReady && worldMapInstance) { attachMapWheelZoom(); worldMapInstance.updateSize(); applyCountryColors(values, total); if ($("countryRank")) $("countryRank").innerHTML = details; } } catch (error) { $("countryMap").innerHTML = '<div class="muted" style="padding:6px 12px">世界地图渲染失败，请刷新重试。</div>'; } }
    function render(s, hours, usage, available = true, projectMetrics = null, workerMetrics = null) { currentSummary = s; currentProjectMetrics = projectMetrics; currentWorkerMetrics = workerMetrics; currentAvailable = available; const scope = selectedScopeText(); if (projectMetrics?.matched) $("requestChartSource").value = "worker"; $("requestScopeText").textContent = scope; $("trafficScopeText").textContent = scope; $("workersScopeText").textContent = scope; $("pagesScopeText").textContent = scope; $("totalRequests").textContent = fmt(projectMetrics?.totalRequests ?? s.totalRequests); $("totalBytes").textContent = bytes(s.totalBytes); $("rangeText").textContent = hours + "h"; renderUsage(usage, projectMetrics); $("analysisBlocked").classList.toggle("privacy-hidden", available); $("aiBtn").disabled = !available; $("chartPanel").classList.toggle("blocked", !available); $("trafficChartPanel").classList.toggle("blocked", !available); $("countryPanel").classList.toggle("blocked", !available); $("ipTableWrap").classList.toggle("blocked", !available); $("hostTableWrap").classList.toggle("blocked", !available); $("ipTable").innerHTML = s.topIPs.map(x => '<tr><td>' + escapeHtml(x.dimensions.clientIP) + '</td><td>' + escapeHtml(x.dimensions.clientCountryName||"-") + '</td><td>' + fmt(x.count) + '</td><td>' + percentText(Number(x.count || 0), s.totalRequests) + '</td></tr>').join(""); $("hostTable").innerHTML = s.topHosts.map(x => '<tr><td>' + escapeHtml(x.dimensions.clientRequestHTTPHost) + '</td><td>' + fmt(x.count) + '</td><td>' + percentText(Number(x.count || 0), s.totalRequests) + '</td></tr>').join(""); try { renderCharts(); } catch (error) { $("requestChartNote").textContent = "折线图渲染失败，请刷新重试。"; } renderCountryMap(s.topCountries, s.totalRequests); }
    function chartOptions(formatter = fmt) { return { responsive:true, maintainAspectRatio:false, plugins:{ legend:{ labels:{ color:"#dbeafe" } }, tooltip:{ callbacks:{ label:(ctx) => ctx.dataset.label + "：" + formatter(ctx.parsed.y) } } }, scales:{ x:{ ticks:{ color:"#8ea3c3", maxTicksLimit:8 }, grid:{ color:"rgba(255,255,255,.06)" } }, y:{ ticks:{ color:"#8ea3c3", callback:(value) => formatter(value) }, grid:{ color:"rgba(255,255,255,.06)" } } } }; }
    function renderLine(target, series, valueKey, label, color, formatter = fmt, total = null) { const labels = series.map(x => shortBeijingTime(x.time)); const values = series.map(x => Number(x[valueKey] || 0)); return new Chart($(target), { type:"line", data:{ labels, datasets:[{ label, data:values, borderColor:color, backgroundColor:color === "#5eead4" ? "rgba(94,234,212,.16)" : "rgba(96,165,250,.14)", tension:.28, fill:true }] }, options:chartOptions(formatter) }); }
    function seriesTotal(series, key) { return (series || []).reduce((sum, item) => sum + Number(item?.[key] || 0), 0); }
    function renderCharts() { if (chart) chart.destroy(); if (trafficChart) trafficChart.destroy(); $("requestChartNote").textContent = ""; if (!currentAvailable) return; const requestSource = $("requestChartSource").value; if (requestSource === "worker") { const series = currentWorkerMetrics?.timeline || []; const total = currentProjectMetrics?.totalRequests ?? seriesTotal(series, "count"); const projectLabel = currentProjectMetrics ? (currentProjectMetrics.projectName || $("projectInput").value.trim() || "当前服务") + " 项目 请求" : "Worker 请求"; $("requestChartTitle").textContent = "请求数折线：" + projectLabel + "（" + fmt(total) + "）"; if (series.length) chart = renderLine("lineChart", series, "count", projectLabel + "数（北京时间）", "#5eead4", fmt, total); else $("requestChartNote").textContent = "当前账号缺少 Account ID 或暂无 Worker 请求数据。"; } else { const total = Number(currentSummary.totalRequests || seriesTotal(currentSummary.timeline, "count")); $("requestChartTitle").textContent = "请求数折线：HTTP 请求（" + fmt(total) + "）"; if (currentSummary.timeline?.length) chart = renderLine("lineChart", currentSummary.timeline, "count", "HTTP 请求数（北京时间）", "#5eead4", fmt, total); } const trafficTotal = Number(currentSummary.totalBytes || seriesTotal(currentSummary.timeline, "bytes")); $("trafficChartTitle").textContent = "流量折线：HTTP 流量（" + chartBytes(trafficTotal) + "）"; if (currentSummary.timeline?.length) trafficChart = renderLine("trafficChart", currentSummary.timeline, "bytes", "HTTP 流量（北京时间）", "#60a5fa", chartBytes, trafficTotal); setTimeout(() => { if (chart) chart.resize(); if (trafficChart) trafficChart.resize(); }, 60); }
    function resizeVisuals() { if (chart) chart.resize(); if (trafficChart) trafficChart.resize(); if (worldMapInstance) worldMapInstance.updateSize(); }
    function renderUsage(u, projectMetrics = null) { const limit = u?.limit || 0; setUsage("workers", u?.workers || 0, limit, false); setUsage("pages", u?.pages || 0, limit, false); setUsage("totalUsage", u?.total || 0, limit, true); $("usageNote").textContent = "同账号 Workers 和 Pages 共享免费 100K 请求额度，每日 GMT+8 刷新额度。"; }
    function setUsage(prefix, value, limit, showLimit) { const pct = limit ? Math.min(100, value / limit * 100) : 0; $(prefix + "Bar").style.width = pct.toFixed(1) + "%"; $(prefix + "Pct").textContent = limit ? pct.toFixed(1) + "%" : "未配置"; $(prefix === "totalUsage" ? "totalUsage" : prefix + "Usage").textContent = limit ? (showLimit ? fmt(value) + " / " + fmt(limit) : fmt(value)) : "未配置 Account ID"; }
    $("refreshBtn").onclick = refresh;
    $("requestChartSource").onchange = renderCharts;
    $("accountSelect").onchange = () => { loadZones(); refresh(); };
    $("zoneSelect").onchange = refresh;
    function openAiConfirm(host) { pendingAiHost = host; const accountText = $("accountSelect").options[$("accountSelect").selectedIndex]?.textContent || ""; const zoneText = $("zoneSelect").options[$("zoneSelect").selectedIndex]?.textContent || "全部区域汇总"; const projectName = $("projectInput").value.trim(); $("aiConfirmAccount").textContent = accountText; $("aiConfirmZone").textContent = zoneText; $("aiConfirmHost").textContent = host; $("aiConfirmProject").textContent = projectName; $("aiConfirmMask").classList.add("open"); }
    function closeAiConfirm() { $("aiConfirmMask").classList.remove("open"); pendingAiHost = ""; }
    async function runAiAnalysis(host) { const btn = $("aiBtn"); const projectName = $("projectInput").value.trim(); btn.disabled = true; btn.textContent = "分析中..."; $("aiResult").textContent = "正在校验服务名 / 项目名数据..."; try { const q = new URLSearchParams({ account: $("accountSelect").value, zone: $("zoneSelect").value, hours: "24", host, projectName }); const checked = await api("/api/analytics?" + q); render(checked.summary, checked.hours, checked.usage, checked.analyticsAvailable !== false, checked.projectMetrics, checked.workerMetrics); if (!checked.projectMetrics || !checked.projectMetrics.matched) throw new Error("服务名 / 项目名参数错误，无法成功获取该服务的项目级 Workers metrics 数据。"); $("aiResult").textContent = "AI 正在分析指定服务的 24 小时数据..."; const data = await api("/api/ai/analyze", { method:"POST", body: JSON.stringify({ account: $("accountSelect").value, zone: $("zoneSelect").value, host, projectName }) }); $("aiResult").innerHTML = renderMarkdown(data.analysis); } catch (err) { $("aiResult").textContent = err.message; } finally { btn.disabled = false; btn.textContent = "AI 分析 24h"; } }
    $("aiBtn").onclick = () => { const host = $("hostInput").value.trim(); const projectName = $("projectInput").value.trim(); if (!session.aiAvailable) { $("aiResult").textContent = "当前 Pages 项目未绑定 Workers AI，请根据仓库 README 在 Functions 设置中添加 AI 绑定后重新部署。"; return; } if (!accountCache.length) { $("aiResult").textContent = NO_ACCOUNT_MESSAGE; return; } if ($("accountSelect").value === "all") { $("aiResult").textContent = "请先选择一个具体账号，再进行 AI 盗用风险分析。"; return; } if (!host) { $("aiResult").textContent = "请先输入主机名，再基于筛选后的数据进行 AI 盗用风险分析。"; return; } if (!projectName) { $("aiResult").textContent = "AI 分析必须输入服务名 / 项目名参数。"; return; } openAiConfirm(host); };
    $("aiConfirmNo").onclick = closeAiConfirm;
    $("aiConfirmMask").onclick = (event) => { if (event.target === $("aiConfirmMask")) closeAiConfirm(); };
    $("aiConfirmYes").onclick = async () => { const host = pendingAiHost; closeAiConfirm(); if (host) await runAiAnalysis(host); };
    window.addEventListener("resize", () => { setTimeout(resizeVisuals, 120); });
    window.addEventListener("orientationchange", () => { setTimeout(resizeVisuals, 260); });
    init().catch(err => { $("aiResult").textContent = err.message; });
  </script>
</body>
</html>`;

const ADMIN_PANEL_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>后台管理</title>
  <style>
    :root { --bg:#0a1020; --panel:#111a2f; --line:#2a3a5d; --text:#eef5ff; --muted:#8ea3c3; --accent:#5eead4; --bad:#fb7185; }
    * { box-sizing:border-box; min-width:0; }
    html, body { max-width:100%; overflow-x:hidden; }
    body { margin:0; background:var(--bg); color:var(--text); font-family:Inter,"PingFang SC","Microsoft YaHei",Arial,sans-serif; }
    header, main { width:min(1120px, calc(100vw - 32px)); margin:auto; }
    header { padding:28px 0; display:flex; justify-content:space-between; gap:16px; align-items:center; }
    main { display:grid; gap:18px; padding-bottom:40px; }
    h1, h2 { margin:0 0 10px; }
    p, label, small { color:var(--muted); }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:22px; padding:20px; overflow:hidden; }
    .grid { display:grid; gap:12px; }
    input, textarea, button { font:inherit; border-radius:13px; }
    input, textarea { width:100%; border:1px solid var(--line); background:#0d172b; color:var(--text); padding:11px; }
    textarea { min-height:120px; resize:vertical; }
    input[type=checkbox] { width:18px; height:18px; min-width:18px; margin:0; accent-color:var(--accent); }
    button { min-width:256px; border:0; background:var(--accent); color:#07101d; font-weight:800; padding:11px 14px; cursor:pointer; }
    header .row button { min-width:auto; }
    .secondary { display:inline-flex; align-items:center; justify-content:center; background:#243655; color:var(--text); border:1px solid var(--line); text-decoration:none; border-radius:13px; padding:11px 14px; font:inherit; font-weight:800; line-height:normal; }
    .danger { background:var(--bad); }
    .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; justify-content:flex-end; }
    .check { display:flex; align-items:center; gap:10px; line-height:1.5; color:var(--muted); }
    .account { display:flex; justify-content:space-between; gap:12px; border-top:1px solid rgba(255,255,255,.08); padding:14px 0; flex-wrap:wrap; }
    .msg { color:var(--muted); white-space:pre-wrap; overflow-wrap:anywhere; }
    .error { color:var(--bad); }
    .account small, .account strong { overflow-wrap:anywhere; word-break:break-word; }
    .modal-mask { position:fixed; inset:0; display:none; place-items:center; padding:18px; background:rgba(3,7,18,.72); z-index:50; }
    .modal-mask.open { display:grid; }
    .modal-card { width:min(420px,100%); background:var(--panel); border:1px solid var(--line); border-radius:22px; padding:20px; box-shadow:0 30px 90px rgba(0,0,0,.45); }
    .modal-card code { display:block; margin:12px 0; padding:12px; border-radius:13px; color:var(--accent); background:#0d172b; overflow-wrap:anywhere; }
    @media (max-width:800px) { header { flex-direction:column; align-items:flex-start; } header > .row { margin-left:0; justify-content:flex-start; } }
    @media (max-width:520px) { header, main { width:min(1120px, calc(100vw - 20px)); } .panel { padding:14px; border-radius:18px; } button, .secondary { width:100%; text-align:center; } }
  </style>
</head>
<body>
  <header>
    <div><h1>后台管理</h1><p>账号配置保存后前端不会展示 Token 或 Zone ID。</p></div>
    <div class="row"><a class="secondary" href="/">返回首页</a><button id="logoutBtn" class="secondary" type="button">退出登录</button></div>
  </header>
  <main>
    <section class="panel grid">
      <h2>添加账号</h2>
      <label>显示名称<input id="accountName" autocomplete="off" placeholder="例如：主账号"></label>
      <label>Cloudflare Account ID<input id="accountId" autocomplete="off" placeholder="用于统计 Workers / Pages 免费额度进度"></label>
      <label>Cloudflare API Token<input id="accountToken" type="password" autocomplete="off" placeholder="保存前会先验证，不会明文展示"></label>
      <label>区域列表<textarea id="zoneText" placeholder="每行一个：Zone ID#显示名称&#10;也可以留空，只统计 Workers/Pages 用量"></textarea></label>
      <small>同一账号可填写多个区域。格式示例：<code>zone_id#example</code>，<code>#</code> 后为后台显示名称。留空时只统计 Workers/Pages 用量，不支持域名请求明细和 AI 分析。</small>
      <div class="row"><button id="addAccountBtn" type="button">验证并保存</button></div>
      <div id="accountMsg" class="msg"></div>
    </section>
    <section>
      <h2>账号列表</h2>
      <div id="accounts" class="msg" style="display:grid;gap:14px">加载中...</div>
    </section>
    <section class="panel grid">
      <h2>公开隐私设置</h2>
      <label class="check"><input id="publicTopIPs" type="checkbox"> 未登录公开 Top IP</label>
      <label class="check"><input id="publicTopHosts" type="checkbox"> 未登录公开 Top Host</label>
      <label class="check"><input id="publicTimeline" type="checkbox"> 未登录公开折线图</label>
      <label class="check"><input id="publicFilters" type="checkbox"> 未登录公开账号/主机筛选</label>
      <label class="check"><input id="hideAiPanel" type="checkbox"> 全局隐藏首页 AI 分析卡片</label>
      <label class="check"><input id="aiVerboseData" type="checkbox"> AI 结果允许引用详细数据</label>
      <div class="row"><button id="savePrivacyBtn" type="button">保存隐私设置</button></div>
      <div id="privacyMsg" class="msg"></div>
    </section>
  </main>
  <div id="deleteConfirmMask" class="modal-mask">
    <div class="modal-card">
      <h2>确认删除账号</h2>
      <p>删除后需要重新添加账号配置。确认删除以下账号？</p>
      <code id="deleteConfirmName"></code>
      <div class="row"><button id="deleteConfirmYes" class="danger" type="button">确认删除</button><button id="deleteConfirmNo" class="secondary" type="button">取消</button></div>
    </div>
  </div>
  <script>
    const $ = (id) => document.getElementById(id);
    let pendingDeleteId = "";
    async function api(path, options = {}) {
      const res = await fetch(path, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
      const contentType = res.headers.get("content-type") || "";
      const data = contentType.includes("application/json") ? await res.json() : { error: await res.text() };
      if (!res.ok) throw new Error(data.message || data.error || "请求失败");
      return data;
    }
    function escapeHtml(value) {
      return String(value || "").replace(/[&<>"]/g, (ch) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[ch]));
    }
    function parseZones(text) {
      return String(text || "").split(/\\r?\\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
        const parts = line.split("#");
        const zoneTag = (parts.shift() || "").trim();
        const name = parts.join("#").trim() || "未命名区域";
        return { zoneTag, name };
      }).filter((zone) => zone.zoneTag);
    }
    async function loadAccounts() {
      const data = await api("/api/accounts");
      if (!data.accounts.length) {
        $("accounts").textContent = "暂无账号";
        return;
      }
      $("accounts").innerHTML = data.accounts.map((account, ai) => '<div class="panel" data-account="' + escapeHtml(account.id) + '" style="display:grid;gap:12px;width:100%;border:1px solid var(--line);border-radius:22px;padding:20px;background:var(--panel)"><label><span style="color:var(--muted)">#' + (ai + 1) + ' 账号显示名称</span><input data-account-name value="' + escapeHtml(account.name) + '" style="margin-top:4px"></label><small>' + escapeHtml(account.createdAt || "") + (account.hasAccountId ? ' · 已配置 Account ID' : ' · 未配置 Account ID') + '</small>' + (account.zones || []).map((zone, zi) => '<div' + (zi ? ' style="border-top:1px solid var(--line);padding-top:8px;margin-top:4px"' : '') + '><div style="display:grid;gap:6px"><span style="color:var(--muted)">区域 ' + (zi + 1) + '</span><input data-zone-id="' + escapeHtml(zone.id) + '" value="' + escapeHtml(zone.name) + '"><button type="button" data-delete-zone="' + escapeHtml(account.id) + '|' + escapeHtml(zone.id) + '" class="secondary" style="width:100%">删除区域</button></div></div>').join("") + '<div style="background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:14px;display:grid;gap:10px;width:100%">' + (account.hasAccountId ? '' : '<label><div style="color:var(--muted);margin-bottom:4px">Cloudflare Account ID</div><input data-account-id value=""></label><button type="button" data-save-account-id="' + escapeHtml(account.id) + '" class="secondary">保存 Account ID</button>') + '<label><div style="color:var(--muted);margin-bottom:4px">添加区域</div><input data-add-zone placeholder="区域 ID 或 ZoneID#名称"></label><button type="button" data-add-zones-id="' + escapeHtml(account.id) + '" class="secondary">添加区域</button></div><div class="row" style="width:100%;flex-direction:column"><button class="secondary" type="button" data-save-id="' + escapeHtml(account.id) + '" style="width:100%">保存名称</button><button class="danger" type="button" data-id="' + escapeHtml(account.id) + '" style="width:100%">删除</button></div></div>').join("");
      document.querySelectorAll("button[data-save-id]").forEach((button) => {
        button.addEventListener("click", async () => {
          const wrap = document.querySelector('[data-account="' + button.dataset.saveId + '"]');
          const zones = [...wrap.querySelectorAll("input[data-zone-id]")].map((input) => ({ id: input.dataset.zoneId, name: input.value.trim() }));
          const accountIdInput = wrap.querySelector("input[data-account-id]");
          const body = { id: button.dataset.saveId, name: wrap.querySelector("input[data-account-name]").value.trim(), zones };
          if (accountIdInput) body.accountId = accountIdInput.value.trim();
          await api("/api/accounts", { method: "PUT", body: JSON.stringify(body) });
          await loadAccounts();
        });
      });
      document.querySelectorAll("button[data-id]").forEach((button) => {
        button.addEventListener("click", async () => {
          pendingDeleteId = button.dataset.id;
          const wrap = document.querySelector('[data-account="' + pendingDeleteId + '"]');
          const name = wrap?.querySelector("input[data-account-name]")?.value || "未命名账号";
          $("deleteConfirmName").textContent = name;
          $("deleteConfirmMask").classList.add("open");
        });
      });
      document.querySelectorAll("button[data-add-zones-id]").forEach((button) => {
        button.addEventListener("click", async () => {
          const wrap = document.querySelector('[data-account="' + button.dataset.addZonesId + '"]');
          const input = wrap?.querySelector("input[data-add-zone]");
          if (!input) return;
          const raw = input.value.trim();
          if (!raw) return;
          const parts = raw.split("#");
          const zoneTag = (parts.shift() || "").trim();
          const name = parts.join("#").trim() || "未命名区域";
          if (!zoneTag) return;
          try {
            await api("/api/accounts", { method: "PATCH", body: JSON.stringify({ id: button.dataset.addZonesId, zones: [{ zoneTag, name }] }) });
            input.value = "";
            await loadAccounts();
          } catch (error) { alert(error.message); }
        });
      });
      document.querySelectorAll("button[data-delete-zone]").forEach((button) => {
        button.addEventListener("click", async () => {
          const [accountId, zoneId] = button.dataset.deleteZone.split("|");
          if (!accountId || !zoneId) return;
          try {
            await api("/api/accounts?id=" + encodeURIComponent(accountId) + "&zoneId=" + encodeURIComponent(zoneId), { method: "DELETE" });
            await loadAccounts();
          } catch (error) { alert(error.message); }
        });
      });
      document.querySelectorAll("button[data-save-account-id]").forEach((button) => {
        button.addEventListener("click", async () => {
          const wrap = document.querySelector('[data-account="' + button.dataset.saveAccountId + '"]');
          const input = wrap?.querySelector("input[data-account-id]");
          if (!input) return;
          const val = input.value.trim();
          if (!val) return;
          try {
            await api("/api/accounts", { method: "PUT", body: JSON.stringify({ id: button.dataset.saveAccountId, accountId: val }) });
            await loadAccounts();
          } catch (error) { alert(error.message); }
        });
      });
    }
    function closeDeleteConfirm() { pendingDeleteId = ""; $("deleteConfirmMask").classList.remove("open"); }
    async function loadPrivacy() {
      const data = await api("/api/privacy");
      for (const key of ["publicTopIPs", "publicTopHosts", "publicTimeline", "publicFilters", "hideAiPanel", "aiVerboseData"]) $(key).checked = Boolean(data.privacy[key]);
    }
    $("addAccountBtn").addEventListener("click", async () => {
      const msg = $("accountMsg");
      msg.classList.remove("error");
        msg.textContent = "正在验证账号和区域...";
      try {
        const payload = { name: $("accountName").value.trim(), accountId: $("accountId").value.trim(), token: $("accountToken").value.trim(), zones: parseZones($("zoneText").value) };
        if (!payload.name || !payload.token || (!payload.accountId && !payload.zones.length)) throw new Error("请填写名称、Token，并至少填写 Account ID 或一个区域");
        const result = await api("/api/accounts", { method: "POST", body: JSON.stringify(payload) });
        $("accountToken").value = "";
        $("accountId").value = "";
        $("zoneText").value = "";
        msg.textContent = result.action === "merged" ? "已合并到已有账号，新增区域 " + result.addedZones + " 个，去重账号 " + (result.mergedDuplicates || 1) + " 个" : "保存成功";
        await loadAccounts();
      } catch (error) {
        msg.classList.add("error");
        msg.textContent = error.message;
      }
    });
    $("savePrivacyBtn").addEventListener("click", async () => {
      const msg = $("privacyMsg");
      msg.classList.remove("error");
      msg.textContent = "保存中...";
      try {
        await api("/api/privacy", { method: "PUT", body: JSON.stringify({ publicTopIPs: $("publicTopIPs").checked, publicTopHosts: $("publicTopHosts").checked, publicTimeline: $("publicTimeline").checked, publicFilters: $("publicFilters").checked, hideAiPanel: $("hideAiPanel").checked, aiVerboseData: $("aiVerboseData").checked }) });
        msg.textContent = "已保存";
      } catch (error) {
        msg.classList.add("error");
        msg.textContent = error.message;
      }
    });
    $("logoutBtn").addEventListener("click", async () => {
      await api("/api/logout", { method: "POST" });
      location.href = "/login";
    });
    $("deleteConfirmNo").addEventListener("click", closeDeleteConfirm);
    $("deleteConfirmMask").addEventListener("click", (event) => { if (event.target === $("deleteConfirmMask")) closeDeleteConfirm(); });
    $("deleteConfirmYes").addEventListener("click", async () => {
      if (!pendingDeleteId) return;
      await api("/api/accounts?id=" + encodeURIComponent(pendingDeleteId), { method: "DELETE" });
      closeDeleteConfirm();
      await loadAccounts();
    });
    Promise.all([loadAccounts(), loadPrivacy()]).catch((error) => {
      $("accounts").textContent = error.message;
      $("accounts").classList.add("error");
    });
  </script>
</body>
</html>`;

const LOGIN_HTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>管理员登录</title><style>*{box-sizing:border-box;min-width:0}html,body{max-width:100%;overflow-x:hidden}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:22px clamp(14px,4vw,44px);background:#0a1020;color:#eef5ff;font-family:Inter,"PingFang SC","Microsoft YaHei",Arial,sans-serif}.card{width:min(420px,100%);background:#111a2f;border:1px solid #2a3a5d;border-radius:24px;padding:28px;box-shadow:0 24px 70px rgba(0,0,0,.28);overflow:hidden}h1{margin:0 0 12px}p{color:#8ea3c3}input,button{width:100%;border-radius:14px;font:inherit}input{border:1px solid #2a3a5d;background:#0d172b;color:#eef5ff;padding:12px;margin:0 0 12px}button{border:0;background:#5eead4;color:#07101d;font-weight:800;padding:12px;cursor:pointer}.msg{color:#fb7185;min-height:22px;margin-top:10px}a{color:#5eead4}@media(max-width:520px){.card{padding:20px;border-radius:18px}}</style></head><body><form class="card" id="form"><h1>管理员登录</h1><p>登录后返回首页查看完整数据。</p><input id="user" autocomplete="username" placeholder="用户名" value="admin"><input id="pass" type="password" autocomplete="current-password" placeholder="密码"><button type="submit">登录</button><div class="msg" id="msg"></div><p><a href="/">返回首页</a></p></form><script>const $=id=>document.getElementById(id);$('form').onsubmit=async e=>{e.preventDefault();$('msg').textContent='';try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('user').value,password:$('pass').value})});const d=await r.json();if(!r.ok)throw new Error(d.message||d.error||'登录失败');location.href='/'}catch(err){$('msg').textContent=err.message}}</script></body></html>`;
