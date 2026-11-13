/* Explicit app ownership: never infer an entire stack from a name prefix. */
window.woowStacks = (() => {
  const stacks = {
    'Pi Agent':['pi-web.service'],
    'Home Assistant':['homeassistant.service','homeassistant-matter.service','homeassistant-mcp.service'],
    'EMQX':['emqx.service','emqx-entrance.service','emqx-mcp-admin.service'],
    'n8n':['n8n.service','n8n-postgres.service','n8n-valkey.service','n8n-runners.service','n8n-webhook.service','n8n-worker.service','n8n-worker-runners.service','n8n-mcp-admin.service'],
    'Nextcloud':['nextcloud-app.service','nextcloud-db.service','nextcloud-redis.service','nextcloud-office.service','nextcloud-gateway.service','nextcloud-mcp-admin.service'],
    'Odoo':['odoo.service','odoo-db.service','odoo-gateway.service','odoo-mcp-admin.service'],
    'LiteLLM':['litellm.service','litellm-postgres.service','litellm-mcp-admin.service'],
    'Hermes':['hermes-agent.service','hermes-postgres.service','hermes-redis.service','hermes-mcp-admin.service','hermes-provision.service'],
    'Omnigent':['omnigent-server.service','omnigent-postgres.service','omnigent-runner.service'],
    'OpenDesign':['open-design.service','open-design-mcp.service','open-design-nginx.service','open-design-terminal.service','opendesign-mcp-admin.service'],
    'code-server':['code-server.service'],
    'Headscale':['headscale.service','headplane.service','headscale-entrance.service','headscale-ngrok.service','headscale-mcp-admin.service'],
    'Cloudflare Tunnel':['woow-cf-tunnel.service'],
    'Immich':['immich-server.service','immich-machine-learning.service','immich-postgres.service','immich-redis.service']
  };
  function members(app, inventory) {
    const allowed = stacks[app.name];
    if (!allowed) return app.other && !app.unmanaged ? [app.main] : [];
    return inventory.filter(u => allowed.includes(u.id));
  }
  function plan(units, direction, inactiveExternal = []) {
    const byId = new Map(units.map(u => [u.id,u]));
    for (const u of units) {
      if (!u.metrics || ['After','Requires','RequiredBy','BoundBy','ConsistsOf'].some(k=>typeof u.metrics[k] !== 'string')) throw Error('無法確認服務依賴，操作已取消。');
      if (direction==='stop') {
        for (const name of `${u.metrics.RequiredBy} ${u.metrics.BoundBy} ${u.metrics.ConsistsOf}`.split(/\s+/)) {
          if (name.endsWith('.service') && !byId.has(name) && !inactiveExternal.includes(name)) throw Error(`服務 ${u.id} 影響組外服務 ${name}，請透過服務管理檢查。`);
        }
      }
    }
    const ordered=[], visiting=new Set(), visited=new Set();
    function visit(u){if(visited.has(u.id))return;if(visiting.has(u.id))throw Error('服務依賴順序有循環，請透過服務管理處理。');visiting.add(u.id);for(const dep of `${u.metrics.Requires} ${u.metrics.After}`.split(/\s+/)){if(byId.has(dep))visit(byId.get(dep));}visiting.delete(u.id);visited.add(u.id);ordered.push(u);}
    units.forEach(visit);
    return direction==='stop'?ordered.reverse():ordered;
  }
  return { members, plan };
})();
