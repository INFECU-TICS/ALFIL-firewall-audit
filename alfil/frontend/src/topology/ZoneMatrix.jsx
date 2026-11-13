import { useEffect, useState } from "react";
import { Loader2, AlertTriangle, Info } from "lucide-react";
import { api } from "../api";

// Celda: verde = solo permite, rojo = solo bloquea, ámbar = ambos, gris = sin reglas (descarte implícito). «!» = regla accept sin restricción de redes ni servicios.
function style(c) {
  if (c.accept && c.deny) return { bg: "#fef3c7", fg: "#92400e", label: `${c.accept}✔ ${c.deny}✖` };
  if (c.accept) return { bg: c.permissive ? "#fee2e2" : "#dcfce7", fg: c.permissive ? "#991b1b" : "#166534", label: `${c.accept}✔` };
  if (c.deny) return { bg: "#fee2e2", fg: "#991b1b", label: `${c.deny}✖` };
  return { bg: "#f3f4f6", fg: "#9ca3af", label: "—" };
}

export default function ZoneMatrix({ auditId }) {
  const [m, setM] = useState(null);
  const [error, setError] = useState("");
  const [sel, setSel] = useState(null);
  useEffect(() => { api.getZoneMatrix(auditId).then(setM).catch((e) => setError(e.message)); }, [auditId]);
  if (error) return <p className="text-sm text-red-600 flex gap-2"><AlertTriangle className="w-4 h-4" /> {error}</p>;
  if (!m) return <p className="text-sm text-gray-500 flex gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Calculando matriz…</p>;
  const cell = sel ? m.cells[sel] : null;
  return (
    <section className="card p-4">
      <h2 className="text-sm font-semibold text-gray-800 mb-1">Matriz de zonas (origen → destino)</h2>
      <p className="text-xs text-gray-500 mb-3">Reglas habilitadas por par de zonas. <span style={{ color: "#166534" }}>✔ permite</span> · <span style={{ color: "#991b1b" }}>✖ bloquea</span> · <b>rojo con ✔</b> = hay una regla accept sin restricción de redes ni servicios · — = sin reglas (descarte implícito). Haga clic en una celda para ver sus reglas.</p>
      <div className="overflow-x-auto">
        <table className="text-xs border-separate" style={{ borderSpacing: 3 }}>
          <thead><tr><th className="text-right pr-2 text-gray-400 font-normal">Origen ↓ / Destino →</th>{m.zones.map((z) => <th key={z} className="font-semibold text-gray-700 px-2">{z}</th>)}</tr></thead>
          <tbody>
            {m.zones.map((s) => (
              <tr key={s}>
                <th className="text-right pr-2 font-semibold text-gray-700 whitespace-nowrap">{s}</th>
                {m.zones.map((d) => {
                  const c = m.cells[`${s}|${d}`]; const st = style(c); const key = `${s}|${d}`;
                  return (
                    <td key={d}>
                      <button className={`w-full min-w-[64px] rounded px-2 py-2 font-semibold ${sel === key ? "ring-2 ring-blue-500" : ""}`} style={{ background: st.bg, color: st.fg }}
                        title={c.rules.map((r) => `${r.action === "accept" ? "✔" : "✖"} ${r.name}`).join("\n") || "Sin reglas"} onClick={() => setSel(key)}>
                        {st.label}{c.permissive ? " !" : ""}
                      </button>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {cell && (
        <div className="mt-3 text-xs text-gray-700">
          <p className="font-semibold">{sel.replace("|", " → ")}</p>
          {cell.rules.length ? (
            <ul className="mt-1 space-y-0.5">{cell.rules.map((r, i) => <li key={i}>{r.action === "accept" ? "✔" : "✖"} {r.name}</li>)}</ul>
          ) : <p className="text-gray-500 mt-1">Sin reglas: el tráfico se descarta por la regla implícita.</p>}
          {cell.no_log > 0 && <p className="mt-1 text-amber-700">{cell.no_log} regla(s) accept sin registro de tráfico.</p>}
        </div>
      )}
      {(m.notes || []).map((n, i) => <p key={i} className="text-[11px] text-gray-500 flex gap-1.5 mt-2"><Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" /> {n}</p>)}
    </section>
  );
}
