// Lógica pura del grafo de topología: filtrado, layout (ELK) y conversión a React Flow. Sin dependencias de DOM.

export const ROLE_COLORS = {
  firewall: "#1e3a8a",
  lan: "#16a34a",
  wan: "#ea580c",
  dmz: "#ca8a04",
  vpn: "#7c3aed",
  wifi: "#0284c7",
  other: "#64748b",
};

const SIZES = {
  firewall: [230, 96],
  interface: [210, 62],
  network: [196, 44],
  router: [196, 48],
  remote_network: [210, 44],
  internet: [140, 66],
  vpn_tunnel: [196, 52],
  remote_site: [210, 52],
  blackhole: [196, 44],
};

export const roleColor = (role) => ROLE_COLORS[role] || ROLE_COLORS.other;

/** Oculta puertos sin configurar y zonas vacías (opcional) y descarta aristas huérfanas. */
export function filterTopology(topo, { showUnconfigured = false, showEmptyZones = false } = {}) {
  let nodes = topo.nodes.filter((n) => showUnconfigured || !(n.type === "interface" && n.data?.unconfigured));
  const used = new Set(nodes.map((n) => n.parent).filter(Boolean));
  if (!showEmptyZones) nodes = nodes.filter((n) => n.type !== "zone" || used.has(n.id));
  const ids = new Set(nodes.map((n) => n.id));
  const edges = topo.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
  return { ...topo, nodes, edges };
}

function toElk(node, childrenOf) {
  if (node.type === "zone") {
    const kids = childrenOf[node.id] || [];
    return {
      id: node.id,
      layoutOptions: {
        "elk.padding": "[top=40,left=18,bottom=18,right=18]",
        "elk.algorithm": "layered",
        "elk.direction": "RIGHT",
        "elk.spacing.nodeNode": "22",
        "elk.layered.spacing.nodeNodeBetweenLayers": "46",
      },
      ...(kids.length ? { children: kids.map((k) => toElk(k, childrenOf)) } : { width: 200, height: 80 }),
    };
  }
  const [width, height] = SIZES[node.type] || [150, 44];
  return { id: node.id, width, height };
}

/** Devuelve { nodes, edges } de React Flow con posiciones calculadas por ELK (jerarquía por zona). */
export async function layoutTopology(topo) {
  const ELK = (await import("elkjs/lib/elk.bundled.js")).default;
  const elk = new ELK();

  const childrenOf = {};
  const roots = [];
  for (const n of topo.nodes) {
    if (n.parent) (childrenOf[n.parent] ||= []).push(n);
    else roots.push(n);
  }
  const graph = {
    id: "root",
    layoutOptions: {
      "elk.algorithm": "layered",
      "elk.direction": "RIGHT",
      "elk.hierarchyHandling": "INCLUDE_CHILDREN",
      "elk.spacing.nodeNode": "34",
      "elk.layered.spacing.nodeNodeBetweenLayers": "80",
      "elk.layered.spacing.edgeNodeBetweenLayers": "24",
    },
    children: roots.map((n) => toElk(n, childrenOf)),
    edges: topo.edges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
  };
  const laid = await elk.layout(graph);

  const pos = {};
  const walk = (elkNode, parentId) => {
    for (const c of elkNode.children || []) {
      pos[c.id] = { x: c.x, y: c.y, width: c.width, height: c.height, parentId };
      walk(c, c.id);
    }
  };
  walk(laid, null);

  const byId = Object.fromEntries(topo.nodes.map((n) => [n.id, n]));
  const nodes = [];
  const visit = (id) => {
    // padres antes que hijos (requisito de React Flow)
    const n = byId[id];
    const p = pos[id];
    if (!n || !p) return;
    const isZone = n.type === "zone";
    nodes.push({
      id,
      type: isZone ? "zoneGroup" : "topo",
      position: { x: p.x, y: p.y },
      ...(p.parentId ? { parentId: p.parentId, extent: "parent" } : {}),
      ...(isZone ? { style: { width: p.width, height: p.height }, zIndex: 0 } : { zIndex: 1 }),
      data: { ...n, width: p.width, height: p.height },
    });
    for (const c of childrenOf[id] || []) visit(c.id);
  };
  roots.forEach((r) => visit(r.id));

  const edges = topo.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: "smoothstep",
    label: e.label || undefined,
    zIndex: 2,
    style: {
      stroke: e.kind === "vpn" ? ROLE_COLORS.vpn : e.dashed ? "#dc2626" : "#94a3b8",
      strokeWidth: e.kind === "interface" ? 2 : 1.5,
      ...(e.dashed ? { strokeDasharray: "6 4" } : {}),
    },
    labelStyle: { fontSize: 10, fill: "#475569" },
    labelBgStyle: { fill: "#fff", fillOpacity: 0.9 },
    data: e,
  }));
  return { nodes, edges };
}

const q = (s) => String(s ?? "").replace(/"/g, "'");

/** Texto Mermaid (flowchart) del grafo visible, para pegar en documentación o informes. */
export function toMermaid(topo) {
  const idx = {};
  topo.nodes.forEach((n, i) => (idx[n.id] = `n${i}`));
  const label = (n) => {
    const extra = n.type === "interface" ? [n.data?.ip && `${n.data.ip}`, n.data?.vlan_id && `VLAN ${n.data.vlan_id}`].filter(Boolean).join(" · ") : "";
    return extra ? `${q(n.label)}<br/>${q(extra)}` : q(n.label);
  };
  const lines = ["flowchart LR"];
  const children = {};
  topo.nodes.forEach((n) => n.parent && (children[n.parent] ||= []).push(n));
  for (const n of topo.nodes.filter((x) => x.type === "zone")) {
    lines.push(`  subgraph ${idx[n.id]}["${q(n.label)}"]`);
    (children[n.id] || []).forEach((c) => lines.push(`    ${idx[c.id]}["${label(c)}"]`));
    lines.push("  end");
  }
  for (const n of topo.nodes.filter((x) => x.type !== "zone" && !x.parent)) lines.push(`  ${idx[n.id]}["${label(n)}"]`);
  for (const e of topo.edges) {
    const arrow = e.dashed ? "-.->" : "-->";
    lines.push(e.label ? `  ${idx[e.source]} ${arrow}|"${q(e.label)}"| ${idx[e.target]}` : `  ${idx[e.source]} ${arrow} ${idx[e.target]}`);
  }
  return lines.join("\n");
}
