import { Handle, Position } from "@xyflow/react";
import { Shield, Network, Router, Globe, Lock, Building2, Ban, Cable, AlertTriangle } from "lucide-react";
import { roleColor } from "./layout";

export const SEV_COLOR = { critical: "#dc2626", warning: "#d97706", info: "#2563eb" };
const SEV_RANK = ["critical", "warning", "info"];
export const worst = (f) => (f && f.length ? SEV_RANK.find((s) => f.some((x) => x.severity === s)) : null);

function Badge({ findings }) {
  const sev = worst(findings);
  if (!sev) return null;
  return (
    <span title={`${findings.length} hallazgo(s)`} className="absolute -top-2 -right-2 min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-bold text-white flex items-center justify-center shadow"
      style={{ background: SEV_COLOR[sev] }}>{findings.length}</span>
  );
}

const ICONS = {
  firewall: Shield,
  interface: Network,
  network: Cable,
  router: Router,
  remote_network: Cable,
  internet: Globe,
  vpn_tunnel: Lock,
  remote_site: Building2,
  blackhole: Ban,
};

const KIND_LABEL = { physical: "Interfaz", vlan: "VLAN", lag: "LAG", bridge: "Bridge" };

function subtitle(d) {
  switch (d.type) {
    case "interface": {
      const parts = [d.data?.ip || (d.data?.unconfigured ? "sin configurar" : "sin IP")];
      if (d.data?.kind === "vlan") parts.push(`VLAN ${d.data.vlan_id}`);
      else if (KIND_LABEL[d.data?.kind] && d.data.kind !== "physical") parts.push(KIND_LABEL[d.data.kind]);
      return parts.join(" · ");
    }
    case "vpn_tunnel": return d.data?.enabled ? "Túnel IPsec" : "Túnel IPsec (inactivo)";
    case "remote_site": return "Sitio remoto";
    case "router": return d.data?.unreachable ? "Salto inalcanzable" : d.data?.gateway ? "Gateway" : "Router";
    case "network": return "Red conectada";
    case "remote_network": return "Red remota";
    case "firewall": return "Firewall";
    case "blackhole": return "Ruta descartada";
    default: return "";
  }
}

export function TopoNode({ data, selected }) {
  const Icon = ICONS[data.type] || Network;
  const color = data.type === "firewall" ? roleColor("firewall") : roleColor(data.data?.role);
  const bad = data.data?.unreachable;
  const dim = (data.type === "interface" && data.data?.up === false) || data.data?.enabled === false;
  const big = data.type === "firewall";
  const sev = worst(data.findings);
  return (
    <div
      className={`relative rounded-lg border bg-white shadow-sm flex items-center gap-2 px-2.5 ${selected ? "ring-2 ring-blue-500" : ""} ${dim ? "opacity-60" : ""}`}
      style={{ width: data.width, height: data.height, borderColor: bad ? "#dc2626" : color, borderLeftWidth: 5, borderStyle: bad ? "dashed" : "solid",
        ...(sev ? { boxShadow: `0 0 0 2px ${SEV_COLOR[sev]}55` } : {}) }}
    >
      <Badge findings={data.findings} />
      <Handle type="target" position={Position.Left} className="!w-1.5 !h-1.5 !bg-slate-400" />
      <div className="rounded-md p-1.5 flex-shrink-0" style={{ background: `${color}1a`, color }}>
        {bad ? <AlertTriangle className="w-4 h-4 text-red-600" /> : <Icon className={big ? "w-6 h-6" : "w-4 h-4"} />}
      </div>
      <div className="min-w-0 leading-tight">
        <p className={`truncate font-semibold text-gray-900 ${big ? "text-sm" : "text-xs"}`} title={data.label}>{data.label}</p>
        <p className="truncate text-[10px] text-gray-500">{subtitle(data)}</p>
      </div>
      <Handle type="source" position={Position.Right} className="!w-1.5 !h-1.5 !bg-slate-400" />
    </div>
  );
}

export function ZoneGroup({ data }) {
  const color = roleColor(data.data?.role);
  return (
    <div className="relative w-full h-full rounded-xl" style={{ background: `${color}0d`, border: `2px dashed ${worst(data.findings) ? SEV_COLOR[worst(data.findings)] : color + "80"}` }}>
      <Badge findings={data.findings} />
      <div className="px-3 py-1.5 flex items-center gap-2">
        <span className="inline-block w-2.5 h-2.5 rounded-full" style={{ background: color }} />
        <span className="text-xs font-bold uppercase tracking-wide" style={{ color }}>{data.label}</span>
        {data.data?.zone_type && <span className="text-[10px] text-gray-500">{data.data.zone_type}</span>}
      </div>
    </div>
  );
}

export const nodeTypes = { topo: TopoNode, zoneGroup: ZoneGroup };
