import { useState, useEffect } from "react";
import { api } from "../api";
import { CheckCircle, XCircle, Loader2, Info } from "lucide-react";

const DEFAULTS = { name: "", host: "", port: 4444, username: "", password: "", verify_ssl: false, api_type: "xml" };

function PrereqBanner({ isRest }) {
  const [publicIp, setPublicIp] = useState(null);

  useEffect(() => {
    fetch("/api/v1/utils/public-ip")
      .then((r) => r.json())
      .then((d) => setPublicIp(d.ip ?? null))
      .catch(() => setPublicIp(null));
  }, []);

  return (
    <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 text-sm text-blue-900">
      <div className="flex items-center gap-1.5 font-semibold mb-2">
        <Info className="w-4 h-4 flex-shrink-0" />
        Requisitos previos en el firewall Sophos
      </div>
      <ol className="list-decimal list-inside space-y-1.5 text-blue-800">
        {isRest ? (
          <li>
            Generar una <span className="font-medium">API key</span> en{" "}
            <span className="font-medium">Administración &rsaquo; Acceso API</span> (Sophos Firewall v23 o superior).
          </li>
        ) : (
          <li>Crear un usuario con perfil <span className="font-medium">Auditor</span> en el firewall.</li>
        )}
        <li>
          Autorizar la IP pública de este servidor en{" "}
          <span className="font-medium">Sistema &rsaquo; Administración &rsaquo; Acceso API</span>:{" "}
          {publicIp
            ? <code className="bg-blue-100 px-1 rounded font-mono">{publicIp}</code>
            : <span className="italic text-blue-500">obteniendo IP…</span>}
        </li>
        <li>Usar el botón <span className="font-medium">Probar conexión</span> antes de guardar.</li>
      </ol>
    </div>
  );
}

export default function ConnectionForm({ initial = {}, onSave, onCancel }) {
  const [form, setForm] = useState({ ...DEFAULTS, ...initial });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [error, setError] = useState("");

  const set = (field) => (e) => {
    const val = e.target.type === "checkbox" ? e.target.checked : e.target.value;
    setForm((f) => ({ ...f, [field]: val }));
    setTestResult(null);
  };

  const isRest = form.api_type === "rest";
  // Al cambiar el tipo de una conexión existente hay que ingresar el nuevo secreto (contraseña ↔ API key)
  const typeChanged = !!initial.id && form.api_type !== (initial.api_type || "xml");

  const setApiType = (api_type) => {
    setForm((f) => ({ ...f, api_type }));
    setTestResult(null);
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await api.testNewConnection({
        host: form.host,
        port: Number(form.port),
        username: isRest ? undefined : form.username,
        password: form.password,
        verify_ssl: form.verify_ssl,
        api_type: form.api_type,
      });
      setTestResult(res);
    } catch (e) {
      setTestResult({ success: false, message: e.message });
    } finally {
      setTesting(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const payload = { ...form, port: Number(form.port), username: isRest ? undefined : form.username };
      if (!payload.password) delete payload.password; // edición sin cambiar el secreto
      await onSave(payload);
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {!initial.id && <PrereqBanner isRest={isRest} />}
      <div>
        <label className="label">Tipo de API</label>
        <div className="grid grid-cols-2 gap-2">
          {[
            ["xml", "API XML", "Usuario y contraseña. Todas las versiones."],
            ["rest", "API REST v23", "API key. Más rápida; incluye MFA de administradores."],
          ].map(([value, title, hint]) => (
            <button key={value} type="button" onClick={() => setApiType(value)}
              className={`text-left rounded-lg border p-2.5 text-sm transition ${form.api_type === value ? "border-blue-500 bg-blue-50 ring-1 ring-blue-500" : "border-gray-200 hover:border-gray-300"}`}>
              <span className="block font-medium text-gray-800">{title}</span>
              <span className="block text-xs text-gray-500 mt-0.5">{hint}</span>
            </button>
          ))}
        </div>
      </div>
      <div>
        <label className="label">Nombre / Empresa</label>
        <input className="input" value={form.name} onChange={set("name")} placeholder="Ej. Cliente ABC - FW Principal" required />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="label">Host / IP</label>
          <input className="input" value={form.host} onChange={set("host")} placeholder="192.168.1.1" required />
        </div>
        <div>
          <label className="label">Puerto</label>
          <input className="input" type="number" value={form.port} onChange={set("port")} min={1} max={65535} required />
        </div>
      </div>
      {!isRest && (
        <div>
          <label className="label">Usuario</label>
          <input className="input" value={form.username} onChange={set("username")} placeholder="admin" required />
        </div>
      )}
      <div>
        <label className="label">{isRest ? "API key" : "Contraseña"}</label>
        <input className="input" type="password" value={form.password} onChange={set("password")}
          placeholder={initial.id && !typeChanged ? "Dejar en blanco para no cambiar" : ""} required={!initial.id || typeChanged} autoComplete="off" />
      </div>
      <div className="flex items-center gap-2">
        <input type="checkbox" id="ssl" checked={form.verify_ssl} onChange={set("verify_ssl")} className="rounded" />
        <label htmlFor="ssl" className="text-sm text-gray-700">Verificar certificado SSL</label>
      </div>

      {/* Test result */}
      {testResult && (
        <div className={`flex items-start gap-2 p-3 rounded-lg text-sm ${testResult.success ? "bg-green-50 text-green-800" : "bg-red-50 text-red-800"}`}>
          {testResult.success
            ? <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            : <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />}
          <div>
            <p className="font-medium">{testResult.success ? "Conexión exitosa" : "Error de conexión"}</p>
            <p className="text-xs mt-0.5">{testResult.message}</p>
            {testResult.details?.firmware && <p className="text-xs">Firmware: {testResult.details.firmware}</p>}
          </div>
        </div>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}

      <div className="flex gap-2 pt-2">
        <button type="button" className="btn-secondary" onClick={handleTest} disabled={testing || !form.host || (!isRest && !form.username) || !form.password}>
          {testing ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
          Probar conexión
        </button>
        <div className="flex-1" />
        <button type="button" className="btn-secondary" onClick={onCancel}>Cancelar</button>
        <button type="submit" className="btn-primary" disabled={saving}>
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
          {initial.id ? "Guardar cambios" : "Crear conexión"}
        </button>
      </div>
    </form>
  );
}
