const BASE = "/api/v1";

async function request(method, path, body) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Error desconocido");
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  // Conexiones
  listConnections:     ()         => request("GET",    "/connections"),
  getConnection:       (id)       => request("GET",    `/connections/${id}`),
  createConnection:    (data)     => request("POST",   "/connections", data),
  updateConnection:    (id, data) => request("PUT",    `/connections/${id}`, data),
  deleteConnection:    (id)       => request("DELETE", `/connections/${id}`),
  testNewConnection:   (data)     => request("POST",   "/connections/test", data),
  testSavedConnection: (id)       => request("POST",   `/connections/${id}/test`),
  queryFirewall:       (id, type) => request("POST",   `/connections/${id}/query`, { query_type: type }),

  // Auditoría — ejecución e historial
  startAudit:    (connectionId) => request("POST", `/audit/${connectionId}/start`),
  listAudits:    (connectionId) => request("GET",  `/audit/${connectionId}/history`),
  getAuditReport:(auditId)      => request("GET",  `/audit/reports/${auditId}`),
  deleteAudit:   (auditId)      => request("DELETE", `/audit/reports/${auditId}`),

  // Exportaciones (URLs para window.open / <a href>)
  exportExcelUrl: (auditId) => `${BASE}/audit/reports/${auditId}/export/excel`,
  exportPdfUrl:   (auditId) => `${BASE}/audit/reports/${auditId}/export/pdf`,
  exportZipUrl:   (auditId) => `${BASE}/audit/reports/${auditId}/export/zip`,
};
