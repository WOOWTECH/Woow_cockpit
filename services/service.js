/* Match Cockpit's shell:style preference and OS theme, including live changes.
 * See cockpit/pkg/lib/cockpit-dark-theme.ts (LGPL-2.1-or-later). */
(() => {
  const system = window.matchMedia('(prefers-color-scheme: dark)');
  function applyTheme(override) {
    let preference = override;
    if (!preference) {
      try { preference = localStorage.getItem('shell:style'); } catch { /* use system preference */ }
    }
    preference ||= 'auto';
    document.documentElement.classList.toggle('pf-v6-theme-dark',
      preference === 'dark' || (preference === 'auto' && system.matches));
  }
  window.addEventListener('storage', event => {
    if (event.key === 'shell:style' || event.key === null) applyTheme();
  });
  window.addEventListener('cockpit-style', event => applyTheme(event.detail?.style));
  system.addEventListener('change', () => applyTheme());
  applyTheme();
})();

/* Cockpit supplies transport and authentication. All service changes go through
 * the installed helper; neither shell commands nor Podman mutations run here. */
(() => {
  "use strict";

  const cockpit = window.cockpit;
  const $ = id => document.getElementById(id);
  const HELPER = "/usr/local/libexec/woowtech-cockpit-services";
  const PAGE_SIZE = 40;
  const POLL_INTERVAL = 30000;
  const ACTIONS = { start: "啟動", stop: "停止", restart: "重新啟動" };
  const KINDS = { local: "本機自訂", quadlet: "Quadlet", system: "系統套件" };
  const STATES = {
    active: "啟用中", inactive: "未啟用", failed: "失敗", activating: "啟動中",
    deactivating: "停止中", reloading: "重新載入中", refreshing: "更新中",
    running: "執行中", exited: "已結束", stopped: "已停止", paused: "已暫停",
    created: "已建立", configured: "已設定", dead: "失敗", unknown: "未知"
  };
  const ACCESS_HELP = "請在 Cockpit 頂端開啟「管理員存取權限」，再重試。";
  const state = {
    scopes: [], scope: "", inventory: null, view: "services", filters: new Map(),
    loading: false, initializing: false, pending: false, stale: false,
    accessDenied: false, permissionRetry: false, lastAttempt: 0,
    details: null, confirmation: null, permission: null, poll: null, reconnectRequired: false
  };

  const string = value => typeof value === "string";
  const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
  const strings = value => Array.isArray(value) && value.every(string);
  const currentScope = () => state.scopes.find(scope => scope.id === state.scope);
  const modalOpen = () => $("details").open || $("action-dialog").open;
  const visible = () => !document.hidden && !cockpit?.hidden;
  const serviceById = id => state.inventory?.services.find(unit => unit.id === id);
  const text = (node, value) => { node.textContent = value; };
  const announce = message => text($("status"), message);
  const stateText = unit => `${STATES[unit.active] || unit.active} · ${unit.active} / ${unit.sub}`;
  const scopeText = scope => `${scope.label} · 擁有者 ${scope.owner} · UID ${scope.uid}`;

  function make(tag, value, className) {
    const node = document.createElement(tag);
    if (value !== undefined) text(node, value);
    if (className) node.className = className;
    return node;
  }

  function setError(id, message) {
    const box = $(id);
    box.hidden = !message;
    text($(id === "page-error" ? "error-message" : `${id}-message`), message || "");
  }

  function parseObject(value) {
    if (!string(value)) return null;
    try {
      const parsed = JSON.parse(value);
      return object(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }

  function helperError(error, output) {
    const payload = parseObject(output) || parseObject(error?.message);
    let reason = string(payload?.error) ? payload.error : error?.message;
    if (!reason) reason = "無法完成要求，請重新整理後再試。";
    const denied = error?.problem === "access-denied" || error?.problem === "not-authorized" ||
      /access.denied|permission.denied|not.authorized|管理員存取|管理權限|administrative access/i.test(reason);
    if (error?.problem === "not-found") reason = "找不到服務管理程式，請確認此主機已安裝服務管理元件。";
    if (error?.problem === "disconnected") {
      reason = "此頁的管理連線已中斷。請按「重新連線」重新載入頁面；先前的服務操作不會自動重做。";
      state.reconnectRequired = true;
      text($("retry"), "重新連線");
    }
    const result = new Error(denied ? `${reason} ${ACCESS_HELP}` : reason);
    result.accessDenied = denied;
    return result;
  }

  // Capture stdout as it arrives: the rejection may only contain ProcessError.
  // Some Cockpit versions also pass remaining stdout as a second argument.
  function call(command, ...args) {
    return new Promise((resolve, reject) => {
      let process;
      let settled = false;
      let timeout;
      let stdout = "";
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (error?.accessDenied) {
          state.accessDenied = true;
          $("access-note").hidden = false;
        }
        if (error) reject(error);
        else resolve(value);
      };
      try {
        process = cockpit.spawn([HELPER, command, ...args], { superuser: "require", err: "message" });
        process.stream(chunk => { stdout += chunk; });
        timeout = setTimeout(() => {
          finish(new Error(command === "action"
            ? "操作回應逾時，結果尚未確認。請重新確認服務狀態後再決定是否操作。"
            : "讀取資料逾時，請重試。"));
          process.close?.("timeout");
        }, command === "action" ? 75000 : 60000);
        process.then(output => {
          const payload = parseObject(stdout + (output || "")) || parseObject(output) || parseObject(stdout);
          if (!payload) finish(new Error("服務管理程式回傳的資料格式不正確，請重試。"));
          else if (string(payload.error)) finish(helperError({ message: payload.error }, JSON.stringify(payload)));
          else finish(null, payload);
        }, (error, output) => finish(helperError(error, stdout + (output || ""))));
      } catch (error) {
        finish(helperError(error));
      }
    });
  }

  function requireData(condition) {
    if (!condition) throw new Error("服務管理程式回傳的資料不完整或範圍不符，請重新整理。");
  }

  function validateInventory(data, scope) {
    requireData(data.scope === scope.id && data.owner === scope.owner &&
      Array.isArray(data.services) && Array.isArray(data.containers) &&
      strings(data.warnings) && string(data.captured_at));
    requireData(data.services.every(unit => object(unit) &&
      ["id", "name", "description", "active", "sub", "enabled"].every(key => string(unit[key])) &&
      Object.hasOwn(KINDS, unit.kind) && strings(unit.containers) &&
      ["can_start", "can_stop", "protected"].every(key => typeof unit[key] === "boolean")));
    requireData(data.containers.every(container => object(container) &&
      ["id", "name", "image", "state", "status", "ports"].every(key => string(container[key])) &&
      (container.unit === null || string(container.unit))));
  }

  function validateDetails(data, id) {
    requireData(object(data.unit) && data.unit.id === id && string(data.logs) &&
      ["id", "description", "active", "sub", "enabled", "source", "fragment"].every(key => string(data.unit[key])) &&
      typeof data.unit.can_start === "boolean" && typeof data.unit.can_stop === "boolean");
    return { ...data.unit, protected: serviceById(id)?.protected === true };
  }

  function filterSet() {
    if (!state.filters.has(state.scope)) {
      const fresh = () => ({ query: "", state: "all", kind: "all", page: 1 });
      state.filters.set(state.scope, { services: fresh(), containers: fresh(), initialized: false });
    }
    return state.filters.get(state.scope);
  }

  function applyDefaults(data) {
    const filters = filterSet();
    if (filters.initialized) return;
    filters.initialized = true;
    if (data.services.length > PAGE_SIZE) {
      if (state.scope === "system") filters.services.state = "active";
      else filters.services.kind = data.services.some(unit => unit.kind === "quadlet") ? "quadlet" : "local";
    }
  }

  function actionReason(unit, verb) {
    if (!unit) return "請先取得最新服務狀態。";
    if (unit.protected) return "受保護的管理服務，無法在此變更狀態。";
    if (["activating", "deactivating", "reloading", "refreshing"].includes(unit.active)) return "服務正在變更狀態，請稍後重新整理。";
    if (verb !== "stop" && unit.id.includes("@.service")) return "服務範本不可直接啟動，請選擇具名的服務實例。";
    if (verb !== "stop" && !unit.can_start) return "此服務不允許啟動或重新啟動。";
    if (verb !== "start" && !unit.can_stop) return "此服務不允許停止或重新啟動。";
    if (verb === "start" && unit.active === "active") return "服務已啟用。";
    if (verb === "stop" && !["active", "activating", "reloading"].includes(unit.active)) return "服務目前未啟用。";
    return "";
  }

  function actionHint(unit) {
    if (unit.protected) return "受保護的管理服務，無法在此變更狀態。";
    if (unit.id.includes("@.service")) return "服務範本不可直接啟動，請選擇具名的服務實例。";
    if (!unit.can_start && !unit.can_stop) return "此服務不允許啟動、停止或重新啟動。";
    if (!unit.can_start) return "此服務不允許啟動或重新啟動。";
    if (!unit.can_stop) return "此服務不允許停止或重新啟動。";
    if (["activating", "deactivating", "reloading", "refreshing"].includes(unit.active)) return "服務正在變更狀態，請稍後重新整理。";
    return "";
  }

  function updateActionButtons(container, unit, busy) {
    container.querySelectorAll("button[data-action]").forEach(button => {
      const reason = actionReason(unit, button.dataset.action);
      button.disabled = busy || Boolean(reason);
      button.title = reason;
      if (unit) button.setAttribute("aria-label", `${ACTIONS[button.dataset.action]} ${unit.id}`);
    });
  }

  function syncControls() {
    const busy = state.loading || state.initializing || state.pending;
    const hasData = Boolean(state.inventory);
    $("scope").disabled = busy || modalOpen() || !state.scopes.length;
    $("refresh").disabled = busy || modalOpen() || !state.scopes.length;
    $("retry").disabled = busy;
    ["search", "state-filter", "kind-filter", "clear-filters"].forEach(id => { $(id).disabled = busy || !hasData; });
    ["services-tab", "containers-tab"].forEach(id => { $(id).disabled = state.pending; });
    $("native-podman").disabled = state.pending || !currentScope();
    $("native-services").disabled = state.pending;
    $("native-services").hidden = state.scope !== "system";
    $("inventory-content").setAttribute("aria-busy", String(state.loading || state.initializing));
    $("services-body").querySelectorAll("tr[data-unit]").forEach(row => {
      updateActionButtons(row, serviceById(row.dataset.unit), busy);
      row.querySelector("[data-open-details]").disabled = busy;
    });
    $("containers-body").querySelectorAll("button").forEach(button => { button.disabled = busy; });
    $("previous-page").disabled = busy || !hasData || filterSet()[state.view].page <= 1;
    $("next-page").disabled = busy || !hasData || filterSet()[state.view].page * PAGE_SIZE >= filteredRows().length;
    $("close-details").disabled = state.pending;
    $("retry-details").disabled = state.pending || Boolean(state.details?.loading);
    $("refresh-logs").disabled = state.pending || !state.details?.unit || state.details.loading || state.details.logsLoading;
    $("details-native-services").disabled = state.pending;
    $("details-native-podman").disabled = state.pending;
    updateActionButtons($("details-actions"), state.details?.unit, state.pending || Boolean(state.details?.loading));
    $("cancel-action").disabled = state.pending;
    $("retry-confirm").disabled = state.pending || Boolean(state.confirmation?.loading);
    $("confirm-action").disabled = state.pending || !state.confirmation?.unit || state.confirmation.loading ||
      Boolean(actionReason(state.confirmation.unit, state.confirmation.verb));
  }

  function containerState(container) {
    if (["running", "active"].includes(container.state)) return "active";
    if (["dead", "failed"].includes(container.state) || /^Exited\s+\([1-9]\d*\)/i.test(container.status)) return "failed";
    return "inactive";
  }

  function filteredRows() {
    if (!state.inventory) return [];
    const filters = filterSet()[state.view];
    const query = filters.query.trim().toLocaleLowerCase();
    const services = state.view === "services";
    const units = new Map(state.inventory.services.map(unit => [unit.id, unit]));
    return state.inventory[state.view].filter(row => {
      const kind = services ? row.kind : units.get(row.unit)?.kind;
      const active = services ? row.active : containerState(row);
      if (filters.kind !== "all" && kind !== filters.kind) return false;
      if (filters.state !== "all" && active !== filters.state) return false;
      const values = services
        ? [row.id, row.name, row.description, ...row.containers]
        : [row.id, row.name, row.image, row.unit || "", row.ports];
      return !query || values.some(value => value.toLocaleLowerCase().includes(query));
    });
  }

  function serviceRow(unit) {
    const row = $("service-row").content.firstElementChild.cloneNode(true);
    row.dataset.unit = unit.id;
    row.dataset.scope = state.scope;
    const title = row.querySelector("[data-open-details]");
    text(title, unit.name || unit.id);
    title.setAttribute("aria-label", `查看 ${unit.id} 的詳細資料與日誌`);
    const values = {
      id: unit.id, description: unit.description, active: STATES[unit.active] || unit.active,
      sub: `${unit.active} / ${unit.sub}`, kind: KINDS[unit.kind], enabled: unit.enabled || "未提供載入方式",
      containers: unit.containers.join("、") || "—"
    };
    Object.entries(values).forEach(([key, value]) => text(row.querySelector(`[data-field="${key}"]`), value));
    row.querySelector(".state").dataset.state = unit.active;
    text(row.querySelector(".action-hint"), actionHint(unit));
    updateActionButtons(row, unit, state.pending || state.loading);
    return row;
  }

  function containerRow(container) {
    const row = $("container-row").content.firstElementChild.cloneNode(true);
    row.dataset.container = container.id;
    row.dataset.scope = state.scope;
    const values = {
      name: container.name, image: container.image, id: container.id,
      state: `${STATES[container.state] || container.state} · ${container.state}`,
      status: container.status, ports: container.ports || "—",
      hint: container.unit ? "透過關聯服務管理啟停" : "唯讀 · 未對應 systemd 服務"
    };
    Object.entries(values).forEach(([key, value]) => text(row.querySelector(`[data-field="${key}"]`), value));
    row.querySelector(".state").dataset.state = container.state;
    const unitCell = row.querySelector('[data-field="unit"]');
    if (container.unit) {
      row.dataset.unit = container.unit;
      const link = make("button", container.unit, "text-button");
      link.type = "button";
      link.dataset.openDetails = "";
      link.setAttribute("aria-label", `查看關聯服務 ${container.unit}`);
      unitCell.replaceChildren(link);
    } else text(unitCell, "未對應服務（唯讀）");
    return row;
  }

  function restoreRowFocus(focus) {
    if (!focus) return;
    const row = [...$("services-body").children, ...$("containers-body").children].find(item =>
      item.dataset.unit === focus.unit && item.dataset.container === focus.container);
    const button = row && [...row.querySelectorAll("button")].find(item =>
      item.dataset.action === focus.action && item.hasAttribute("data-open-details") === focus.details &&
      item.hasAttribute("data-open-podman") === focus.podman);
    button?.focus({ preventScroll: true });
  }

  function render() {
    const active = document.activeElement;
    const activeRow = active?.closest("tbody tr");
    const focus = activeRow ? {
      unit: activeRow.dataset.unit, container: activeRow.dataset.container, action: active.dataset.action,
      details: active.hasAttribute("data-open-details"), podman: active.hasAttribute("data-open-podman")
    } : null;
    const filters = filterSet()[state.view];
    $("search").value = filters.query;
    $("state-filter").value = filters.state;
    $("kind-filter").value = filters.kind;
    ["services", "containers"].forEach(view => {
      const selected = view === state.view;
      $(`${view}-tab`).setAttribute("aria-selected", String(selected));
      $(`${view}-tab`).tabIndex = selected ? 0 : -1;
      $(`${view}-panel`).hidden = !selected;
    });
    text($("service-count"), state.inventory?.services.length ?? "—");
    text($("container-count"), state.inventory?.containers.length ?? "—");
    const rows = filteredRows();
    const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
    filters.page = Math.min(Math.max(1, filters.page), pages);
    const start = (filters.page - 1) * PAGE_SIZE;
    const nodes = rows.slice(start, start + PAGE_SIZE).map(state.view === "services" ? serviceRow : containerRow);
    $("services-body").replaceChildren(...(state.view === "services" ? nodes : []));
    $("containers-body").replaceChildren(...(state.view === "containers" ? nodes : []));
    $("services-table").hidden = state.view !== "services" || !rows.length;
    $("containers-table").hidden = state.view !== "containers" || !rows.length;
    $("empty-state").hidden = rows.length > 0;
    if (!state.inventory) {
      text($("empty-title"), state.loading || state.initializing ? "正在載入…" : "目前無法載入資料");
      text($("empty-description"), "請確認管理範圍與管理員存取權限，或使用上方的重試按鈕。");
    } else if (!rows.length) {
      const any = state.inventory[state.view].length > 0;
      text($("empty-title"), any ? "沒有符合條件的項目" : state.view === "services" ? "此範圍沒有服務" : "此範圍沒有可顯示的容器");
      text($("empty-description"), any ? "請調整搜尋與篩選條件，或選擇「顯示全部」。" : "可切換管理範圍或重新整理；若有讀取限制，會顯示在上方提示中。");
    }
    text($("filter-note"), state.view === "containers"
      ? "類型篩選依關聯的服務判斷；選擇全部類型可包含未對應服務的唯讀容器。"
      : `目前篩選：${$("state-filter").selectedOptions[0].textContent}、${$("kind-filter").selectedOptions[0].textContent}。選擇「顯示全部」可查看所有服務。`);
    text($("page-summary"), state.inventory
      ? `${rows.length ? start + 1 : 0}–${Math.min(start + PAGE_SIZE, rows.length)} / ${rows.length} 筆 · 第 ${filters.page} / ${pages} 頁`
      : "每頁最多 40 筆");
    const captured = state.inventory?.captured_at;
    const date = captured ? new Date(captured) : null;
    text($("captured-at"), date && !Number.isNaN(date.getTime())
      ? `${state.stale ? "上次成功更新" : "更新於"} ${date.toLocaleString("zh-TW", { hour12: false })}` : "尚未更新");
    const warnings = state.inventory?.warnings || [];
    $("warnings").hidden = !warnings.length;
    text($("warnings-title"), `資料提示（${warnings.length}）`);
    $("warning-list").replaceChildren(...warnings.map(warning => make("li", warning)));
    syncControls();
    restoreRowFocus(focus);
  }

  function showScope() {
    const scope = currentScope();
    text($("scope-owner"), scope ? `${scopeText(scope)} · ${scope.id === "system" ? "系統層級服務" : "使用者層級服務"}` : "尚未取得管理範圍。");
    if (scope) $("native-podman").title = `開啟原生頁，並確認擁有者為 ${scope.owner}（UID ${scope.uid}）`;
    $("native-podman-hint").hidden = !scope || scope.id === "system";
    text($("native-podman-hint"), scope ? `原生 Podman 的 Owner 可選 ${scope.owner}；Show 用來篩選容器狀態。` : "");
  }

  async function initialize() {
    if (state.initializing || state.loading || state.pending) return;
    state.initializing = true;
    setError("page-error", "");
    announce("正在載入管理範圍…");
    syncControls();
    let loaded = false;
    try {
      const data = await call("scopes");
      requireData(Array.isArray(data.scopes) && data.scopes.length > 0 && data.scopes.every(scope =>
        object(scope) && string(scope.id) && string(scope.label) && string(scope.owner) &&
        Number.isSafeInteger(scope.uid) && scope.uid >= 0 && (scope.id !== "system" || scope.uid === 0)) &&
        string(data.default_scope) && data.scopes.some(scope => scope.id === data.default_scope));
      state.scopes = data.scopes;
      const preferred = data.scopes.find(scope => scope.id === data.default_scope && scope.id !== "system") ||
        data.scopes.find(scope => scope.id !== "system") || data.scopes.find(scope => scope.id === data.default_scope);
      state.scope = preferred.id;
      $("scope").replaceChildren(...data.scopes.map(scope => {
        const option = make("option", `${scope.label} · ${scope.owner}`);
        option.value = scope.id;
        return option;
      }));
      $("scope").value = state.scope;
      state.accessDenied = false;
      $("access-note").hidden = true;
      showScope();
      loaded = true;
    } catch (error) {
      setError("page-error", error.message);
      announce("管理範圍載入失敗。");
    } finally {
      state.initializing = false;
    }
    if (loaded) await refreshInventory();
    else render();
    retryAfterPermission();
  }

  async function refreshInventory({ quiet = false, afterAction = false } = {}) {
    if (state.loading || state.initializing || !currentScope() || (state.pending && !afterAction)) return false;
    const scope = currentScope();
    state.loading = true;
    state.lastAttempt = Date.now();
    setError("page-error", "");
    if (!quiet) announce(`正在載入 ${scope.label}…`);
    syncControls();
    let success = false;
    try {
      const data = await call("inventory", scope.id);
      validateInventory(data, scope);
      if (state.scope !== scope.id) return false;
      state.inventory = data;
      state.stale = false;
      state.accessDenied = false;
      $("access-note").hidden = true;
      applyDefaults(data);
      if (!quiet) announce(`已更新 ${scope.label}：${data.services.length} 個服務、${data.containers.length} 個容器。`);
      success = true;
    } catch (error) {
      state.stale = Boolean(state.inventory);
      setError("page-error", `${error.message}${state.inventory ? " 目前顯示上次成功取得的資料。" : ""}`);
      announce("資料更新失敗，請重試。");
    } finally {
      state.loading = false;
      render();
      retryAfterPermission();
    }
    return success;
  }

  function jumpPodman(scope = currentScope()) {
    if (scope && !state.pending) cockpit.jump(`/podman#/?owner=${scope.uid}`);
  }

  function jumpServices(scope = currentScope(), unit = "") {
    if (scope?.id === "system" && !state.pending) cockpit.jump(`/system/services#/${encodeURIComponent(unit)}?owner=system`);
  }

  async function loadDetails() {
    const context = state.details;
    if (!context || context.loading || context.logsLoading) return;
    context.loading = true;
    context.unit = null;
    setError("details-error", "");
    text($("details-status"), "正在載入服務詳細資料…");
    text($("logs-status"), "");
    syncControls();
    try {
      const data = await call("details", context.scope.id, context.id);
      const unit = validateDetails(data, context.id);
      if (state.details !== context) return;
      context.unit = unit;
      const fields = [
        ["服務單元", unit.id], ["描述", unit.description], ["目前狀態", stateText(unit)],
        ["載入方式", unit.enabled || "未提供"], ["來源", unit.source || "未提供"],
        ["單元檔案", unit.fragment || "未提供"]
      ];
      if (object(unit.metrics)) {
        const values = unit.metrics;
        const labels = {MainPID:"主程序 PID", MemoryCurrent:"目前記憶體", CPUUsageNSec:"累計 CPU 時間", TasksCurrent:"目前工作數",
          NRestarts:"自動重啟次數", ActiveEnterTimestamp:"最近啟動", InactiveEnterTimestamp:"最近停止", ExecMainStatus:"主程序結束碼",
          Type:"服務模式", Restart:"重啟規則", Requires:"必要相依", Wants:"選用相依", After:"啟動順序在其後", TriggeredBy:"觸發單元"};
        for (const [key, label] of Object.entries(labels)) {
          let value = values[key];
          if (!string(value) || !value || value === '[not set]' || value === '18446744073709551615') value = "未提供";
          else if (key === 'MemoryCurrent' && /^\d+$/.test(value)) value = `${(Number(value) / 1048576).toFixed(1)} MiB`;
          else if (key === 'CPUUsageNSec' && /^\d+$/.test(value)) value = `${(Number(value) / 1e9).toFixed(2)} 秒`;
          fields.push([label, value]);
        }
        fields.push(["最近執行結果", string(unit.result) && unit.result ? unit.result : "未提供"]);
      }
      $("details-fields").replaceChildren(...fields.flatMap(([label, value]) => [make("dt", label), make("dd", value)]));
      text($("details-action-hint"), actionHint(unit));
      text($("logs"), data.logs || "目前沒有日誌。");
      text($("details-status"), "詳細資料已更新。");
    } catch (error) {
      if (state.details !== context) return;
      setError("details-error", error.message);
      text($("details-status"), "詳細資料讀取失敗。");
      text($("logs"), "目前無法取得日誌，請重試詳細資料。");
    } finally {
      context.loading = false;
      if (state.details === context) syncControls();
      retryAfterPermission();
    }
  }

  function openDetails(id, trigger) {
    if (state.pending || state.loading || modalOpen() || !currentScope()) return;
    state.details = { id, scope: currentScope(), unit: null, loading: false, logsLoading: false, trigger };
    text($("details-title"), id);
    text($("details-context"), scopeText(state.details.scope));
    $("details-fields").replaceChildren();
    text($("details-action-hint"), "");
    text($("logs"), "正在載入日誌…");
    $("details-native-services").hidden = state.scope !== "system";
    $("details").showModal();
    loadDetails();
  }

  async function refreshLogs() {
    const context = state.details;
    if (!context?.unit || context.loading || context.logsLoading || state.pending) return;
    context.logsLoading = true;
    text($("logs-status"), "正在更新日誌…");
    syncControls();
    try {
      const data = await call("logs", context.scope.id, context.id);
      requireData(string(data.logs));
      if (state.details !== context) return;
      text($("logs"), data.logs || "目前沒有日誌。");
      text($("logs-status"), "日誌已更新。");
    } catch (error) {
      if (state.details === context) text($("logs-status"), `${error.message} 日誌未更新。`);
    } finally {
      context.logsLoading = false;
      if (state.details === context) syncControls();
      retryAfterPermission();
    }
  }

  function openConfirmation(unit, verb, trigger) {
    if (!Object.hasOwn(ACTIONS, verb) || state.pending || state.loading || state.confirmation || actionReason(unit, verb)) return;
    state.confirmation = { id: unit.id, name: unit.name || unit.id, verb, scope: currentScope(), unit: null, loading: false, trigger };
    text($("action-title"), `確認${ACTIONS[verb]}服務`);
    text($("action-description"), `即將${ACTIONS[verb]}「${state.confirmation.name}」。`);
    text($("confirm-unit"), unit.id);
    text($("confirm-scope"), scopeText(state.confirmation.scope));
    text($("confirm-state"), stateText(unit));
    text($("confirm-action"), `確認${ACTIONS[verb]}`);
    text($("confirm-hint"), verb === "start" ? "確認後將啟動此服務。" : "此操作可能中斷服務及其關聯容器的連線。" );
    $("action-dialog").showModal();
    loadConfirmation();
  }

  async function loadConfirmation() {
    const context = state.confirmation;
    if (!context || context.loading || state.pending) return;
    context.loading = true;
    context.unit = null;
    setError("confirm-error", "");
    text($("confirm-status"), "正在確認最新狀態…");
    syncControls();
    try {
      const data = await call("details", context.scope.id, context.id);
      const unit = validateDetails(data, context.id);
      if (state.confirmation !== context) return;
      context.unit = unit;
      text($("confirm-state"), stateText(unit));
      text($("confirm-status"), actionReason(unit, context.verb) || "已取得最新狀態，請確認是否執行。" );
    } catch (error) {
      if (state.confirmation !== context) return;
      setError("confirm-error", error.message);
      text($("confirm-status"), "無法確認目前狀態，尚未執行操作。");
    } finally {
      context.loading = false;
      if (state.confirmation === context) syncControls();
      retryAfterPermission();
    }
  }

  async function performAction() {
    const context = state.confirmation;
    if (!context?.unit || context.loading || state.pending || actionReason(context.unit, context.verb)) return;
    state.pending = true;
    setError("confirm-error", "");
    text($("confirm-status"), `正在${ACTIONS[context.verb]} ${context.id}，請稍候…`);
    text($("confirm-action"), "執行中…");
    syncControls();
    let succeeded = false;
    let result;
    try {
      result = await call("action", context.scope.id, context.id, context.verb);
      requireData(result.ok === true && result.unit === context.id && result.action === context.verb && string(result.active) && string(result.sub));
      succeeded = true;
    } catch (error) {
      context.unit = null;
      setError("confirm-error", `${error.message} 請重新確認狀態後再決定是否操作。`);
      text($("confirm-status"), "操作未確認完成；不會自動重送操作。");
    }
    // An error can follow a completed systemd job (for example a lost reply).
    // Always read back inventory; retrying a mutation still requires a new click.
    try {
      const refreshed = await refreshInventory({ afterAction: true, quiet: true });
      if (state.details) await loadDetails();
      if (succeeded) {
        announce(`${context.id} 的${ACTIONS[context.verb]}要求已完成；目前${stateText(result)}。${refreshed ? "清單已更新。" : "清單更新失敗，請重新整理。"}`);
        $("action-dialog").close();
      }
    } finally {
      state.pending = false;
      text($("confirm-action"), `確認${ACTIONS[context.verb]}`);
      syncControls();
      retryAfterPermission();
    }
  }

  // Only reads are retried when Cockpit grants administrative access. A failed
  // action is never replayed; its confirmation is refreshed for another click.
  async function retryAfterPermission() {
    if (!state.permissionRetry || state.permission?.allowed !== true || state.pending || state.loading || state.initializing ||
      state.details?.loading || state.details?.logsLoading || state.confirmation?.loading) return;
    state.permissionRetry = false;
    state.accessDenied = false;
    $("access-note").hidden = true;
    if (!state.scopes.length) await initialize();
    else {
      if (state.confirmation) await loadConfirmation();
      if (state.details) await loadDetails();
      if (!modalOpen()) await refreshInventory();
    }
  }

  function permissionChanged() {
    if (state.permission.allowed === true && state.accessDenied) {
      state.permissionRetry = true;
      retryAfterPermission();
    }
  }

  function poll() {
    if (visible() && !state.pending && !state.loading && !state.initializing && !modalOpen() &&
      !state.accessDenied && currentScope() && Date.now() - state.lastAttempt >= POLL_INTERVAL) refreshInventory({ quiet: true });
  }

  function selectView(view) {
    if (state.pending) return;
    state.view = view;
    render();
  }

  $("scope").addEventListener("change", () => {
    if (state.pending || state.loading || modalOpen()) return;
    if (!state.scopes.some(scope => scope.id === $("scope").value)) return;
    state.scope = $("scope").value;
    state.inventory = null;
    state.stale = false;
    showScope();
    refreshInventory();
    render();
  });
  $("refresh").addEventListener("click", () => refreshInventory());
  $("retry").addEventListener("click", () => {
    if (state.reconnectRequired && !state.pending) window.location.reload();
    else if (state.scopes.length) refreshInventory();
    else initialize();
  });
  $("native-services").addEventListener("click", () => jumpServices());
  $("native-podman").addEventListener("click", () => jumpPodman());
  $("details-native-services").addEventListener("click", () => jumpServices(state.details?.scope, state.details?.id));
  $("details-native-podman").addEventListener("click", () => jumpPodman(state.details?.scope));
  $("search").addEventListener("input", () => {
    filterSet()[state.view].query = $("search").value;
    filterSet()[state.view].page = 1;
    render();
  });
  ["state", "kind"].forEach(key => $(`${key}-filter`).addEventListener("change", () => {
    filterSet()[state.view][key] = $(`${key}-filter`).value;
    filterSet()[state.view].page = 1;
    render();
  }));
  $("clear-filters").addEventListener("click", () => {
    Object.assign(filterSet()[state.view], { query: "", state: "all", kind: "all", page: 1 });
    render();
    $("search").focus();
  });
  ["services", "containers"].forEach(view => {
    $(`${view}-tab`).addEventListener("click", () => selectView(view));
    $(`${view}-tab`).addEventListener("keydown", event => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === "Home" ? "services" : event.key === "End" ? "containers" : view === "services" ? "containers" : "services";
      selectView(next);
      $(`${next}-tab`).focus();
    });
  });
  ["previous", "next"].forEach(direction => $(`${direction}-page`).addEventListener("click", () => {
    filterSet()[state.view].page += direction === "next" ? 1 : -1;
    render();
    $(`${state.view}-panel`).focus({ preventScroll: true });
  }));
  ["services-body", "containers-body"].forEach(id => $(id).addEventListener("click", event => {
    const button = event.target.closest("button");
    const row = button?.closest("tr");
    if (!button || button.disabled || !row || row.dataset.scope !== state.scope) return;
    if (button.hasAttribute("data-open-podman")) jumpPodman();
    else if (button.hasAttribute("data-open-details")) openDetails(row.dataset.unit, button);
    else if (button.dataset.action) openConfirmation(serviceById(row.dataset.unit), button.dataset.action, button);
  }));
  $("details-actions").addEventListener("click", event => {
    const button = event.target.closest("button[data-action]");
    if (button && !button.disabled) openConfirmation(state.details?.unit, button.dataset.action, button);
  });
  $("close-details").addEventListener("click", () => { if (!state.pending) $("details").close(); });
  $("cancel-action").addEventListener("click", () => { if (!state.pending) $("action-dialog").close(); });
  $("confirm-action").addEventListener("click", performAction);
  $("retry-confirm").addEventListener("click", loadConfirmation);
  $("retry-details").addEventListener("click", loadDetails);
  $("refresh-logs").addEventListener("click", refreshLogs);
  ["details", "action-dialog"].forEach(id => {
    $(id).addEventListener("cancel", event => { if (state.pending) event.preventDefault(); });
    $(id).addEventListener("close", () => {
      const key = id === "details" ? "details" : "confirmation";
      const trigger = state[key]?.trigger;
      state[key] = null;
      syncControls();
      if (trigger?.isConnected && !trigger.disabled) trigger.focus({ preventScroll: true });
      else if (id === "action-dialog" && $("details").open) $("close-details").focus();
      else $(`${state.view}-tab`).focus({ preventScroll: true });
    });
  });

  if (!cockpit?.spawn || !cockpit?.permission || !cockpit?.jump) {
    setError("page-error", "無法載入 Cockpit 連線元件，請從 Cockpit 的「服務管理」選單開啟此頁。");
    announce("Cockpit 連線元件尚未就緒。");
    $("retry").hidden = true;
    render();
    return;
  }
  try {
    state.permission = cockpit.permission({ admin: true });
    state.permission.addEventListener("changed", permissionChanged);
  } catch {
    // spawn still provides the native privilege check and actionable errors.
    text($("access-note"), `${ACCESS_HELP}啟用後請按「重試」。`);
  }
  cockpit.addEventListener("visibilitychange", poll);
  document.addEventListener("visibilitychange", poll);
  state.poll = setInterval(poll, POLL_INTERVAL);
  window.addEventListener("pagehide", () => {
    clearInterval(state.poll);
    state.permission?.removeEventListener("changed", permissionChanged);
    state.permission?.close?.();
    cockpit.removeEventListener("visibilitychange", poll);
    document.removeEventListener("visibilitychange", poll);
  });
  initialize();
})();
