// Settings — gateway connection, API/admin credentials (kept in sessionStorage,
// never hard-coded), tenant list, and firewall configuration surface.
import { useEffect, useState } from "react";
import { getKeys, setKeys, listTenants } from "../api";
import { Panel } from "../components/ui";
import { Icon } from "../components/icons";
import { useGateway } from "../lib/useGateway";
import { useToast } from "../components/Toaster";
import { useTheme, setTheme, type Theme } from "../lib/theme";

const THEMES: { value: Theme; label: string; icon: "eye" | "sparkles"; hint: string }[] = [
  { value: "dark", label: "Dark", icon: "eye", hint: "Enterprise SOC (default)" },
  { value: "light", label: "Light", icon: "sparkles", hint: "Bright / high-contrast" },
];

export default function Settings() {
  const gw = useGateway();
  const toast = useToast();
  const theme = useTheme();
  const k = getKeys();
  const [api, setApi] = useState(k.apiKey);
  const [admin, setAdmin] = useState(k.adminKey);
  const [tenant, setTenant] = useState(k.tenant);
  const [tenants, setTenants] = useState<any[] | null>(null);
  const [tenantErr, setTenantErr] = useState("");

  const loadTenants = () => {
    listTenants()
      .then((t) => { setTenants(t); setTenantErr(""); })
      .catch((e) => setTenantErr(String(e?.message || e)));
  };
  useEffect(() => { if (admin) loadTenants(); /* eslint-disable-next-line */ }, []);

  const save = () => {
    setKeys(api, admin, tenant);
    toast({ kind: "success", title: "Credentials saved", body: "Stored in this browser session only." });
    if (admin) loadTenants();
  };

  const statusColor = gw === "online" ? "#2dd4a7" : gw === "checking" ? "#ffb454" : "#64748b";

  return (
    <div className="space-y-4">
      <Panel title="Appearance" icon="sparkles" subtitle="Theme is saved on this device">
        <div className="grid grid-cols-2 gap-3 max-w-md">
          {THEMES.map((t) => {
            const active = theme === t.value;
            return (
              <button
                key={t.value}
                onClick={() => setTheme(t.value)}
                className={`rounded-xl p-3 text-left transition-all border ${
                  active ? "border-aegis-accent ring-1 ring-inset ring-aegis-accent/40 bg-aegis-accent/10" : "border-white/[0.06] bg-white/[0.02] hover:bg-white/[0.05]"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`grid place-items-center w-8 h-8 rounded-lg ${active ? "bg-aegis-accent text-white" : "bg-white/[0.05] text-slate-300"}`}>
                    <Icon name={t.icon} size={16} />
                  </span>
                  <div>
                    <div className="text-sm font-semibold text-slate-100">{t.label}</div>
                    <div className="text-[11px] text-slate-500">{t.hint}</div>
                  </div>
                  {active && <Icon name="check" size={16} className="ml-auto text-aegis-accent" />}
                </div>
              </button>
            );
          })}
        </div>
      </Panel>

      <Panel title="Gateway Connection" icon="server" subtitle="Live status of the LLM Firewall Platform backend">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full animate-pulse" style={{ background: statusColor }} />
            <span className="text-sm font-semibold" style={{ color: statusColor }}>
              {gw === "online" ? "Online" : gw === "checking" ? "Checking…" : "Offline"}
            </span>
          </div>
          <span className="text-xs text-slate-500">
            {gw === "online"
              ? "Detections run on the FastAPI gateway (authoritative)."
              : "Gateway unreachable — detection runs on the in-browser engine. The dashboard stays fully functional."}
          </span>
        </div>
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Panel title="Credentials" icon="lock" subtitle="Session-scoped · never persisted to disk">
          <div className="space-y-3">
            <label className="block">
              <span className="kpi-label">Tenant API key (Bearer)</span>
              <input className="mt-1 font-mono text-xs" value={api} onChange={(e) => setApi(e.target.value)} placeholder="ak_….secret" />
            </label>
            <label className="block">
              <span className="kpi-label">Admin key (X-Admin-Key)</span>
              <input className="mt-1 font-mono text-xs" type="password" value={admin} onChange={(e) => setAdmin(e.target.value)} placeholder="admin key" />
            </label>
            <label className="block">
              <span className="kpi-label">Tenant ID</span>
              <input className="mt-1" value={tenant} onChange={(e) => setTenant(e.target.value)} />
            </label>
            <button className="btn w-full" onClick={save}>
              <Icon name="check" size={14} /> Save credentials
            </button>
          </div>
        </Panel>

        <Panel title="Tenants" icon="users" subtitle="Registered organizations on this gateway">
          {tenantErr ? (
            <div className="text-xs text-slate-500">
              Enter an admin key and save to load tenants. <span className="text-slate-600">({tenantErr})</span>
            </div>
          ) : !tenants ? (
            <div className="text-xs text-slate-500">No admin key set — tenant list unavailable in offline mode.</div>
          ) : tenants.length === 0 ? (
            <div className="text-xs text-slate-500">No tenants registered.</div>
          ) : (
            <div className="space-y-2">
              {tenants.map((t) => (
                <div key={t.tenant_id} className="flex items-center justify-between rounded-lg p-2.5 bg-white/[0.02] border border-white/[0.06]">
                  <div>
                    <div className="text-sm text-slate-200">{t.name}</div>
                    <div className="text-[11px] text-slate-500 font-mono">{t.tenant_id}</div>
                  </div>
                  <div className="text-right">
                    <span className={`pill ${t.fail_mode === "closed" ? "bg-aegis-ok/15 text-aegis-ok" : "bg-aegis-warn/15 text-aegis-warn"}`}>
                      fail-{t.fail_mode}
                    </span>
                    <div className="text-[11px] text-slate-500 mt-1">policy v{t.policy_version}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
