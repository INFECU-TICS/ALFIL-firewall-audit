import { useState, useEffect } from "react";
import { api } from "../api";
import { CheckCircle, XCircle, Loader2, Info } from "lucide-react";

const DEFAULTS = { name: "", host: "", port: 4444, username: "", password: "", verify_ssl: false };

function PrereqBanner() {
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
        <li>Crear un usuario con perfil <span className="font-medium">Auditor</span> en el firewall.</li>
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

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await api.testNewConnection({
        host: form.host,
        port: Number(form.port),
        username: form.username,
        password: form.password,
        verify_ssl: form.verify_ssl,
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
      await onSave({ ...form, port: Number(form.port) });
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {!initial.id && <PrereqBanner />}
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
      <div>
        <label className="label">Usuario</label>
        <input className="input" value={form.username} onChange={set("username")} placeholder="admin" required />
      </div>
      <div>
        <label className="label">Contraseña</label>
        <input className="input" type="password" value={form.password} onChange={set("password")}
          placeholder={initial.id ? "Dejar en blanco para no cambiar" : ""} required={!initial.id} />
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
        <button type="button" className="btn-secondary" onClick={handleTest} disabled={testing || !form.host || !form.username || !form.password}>
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
