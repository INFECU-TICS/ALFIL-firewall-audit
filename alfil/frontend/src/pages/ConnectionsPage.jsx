import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, Pencil, Trash2, Play, Wifi, WifiOff, Loader2, AlertCircle, Database } from "lucide-react";
import { api } from "../api";
import Modal from "../components/Modal";
import ConfirmModal from "../components/ConfirmModal";
import ConnectionForm from "../components/ConnectionForm";

function StatusDot({ active }) {
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${active ? "bg-green-500" : "bg-gray-300"}`} />;
}

export default function ConnectionsPage() {
  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [modal, setModal] = useState(null);       // null | "create" | {connection obj}
  const [confirmDelete, setConfirmDelete] = useState(null); // null | {id, name}
  const [deletingId, setDeletingId] = useState(null);
  const [testingId, setTestingId] = useState(null);
  const [testResults, setTestResults] = useState({});
  const navigate = useNavigate();

  const load = async () => {
    setLoading(true);
    try { setConnections(await api.listConnections()); setError(""); }
    catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (data) => { await api.createConnection(data); setModal(null); load(); };
  const handleUpdate = async (data) => { await api.updateConnection(modal.id, data); setModal(null); load(); };

  const handleDeleteConfirmed = async () => {
    const { id } = confirmDelete;
    setConfirmDelete(null);
    setDeletingId(id);
    try { await api.deleteConnection(id); load(); }
    catch (e) { alert(e.message); }
    finally { setDeletingId(null); }
  };

  const handleTest = async (id) => {
    setTestingId(id);
    setTestResults((r) => ({ ...r, [id]: null }));
    try {
      const res = await api.testSavedConnection(id);
      setTestResults((r) => ({ ...r, [id]: res }));
    } catch (e) {
      setTestResults((r) => ({ ...r, [id]: { success: false, message: e.message } }));
    } finally {
      setTestingId(null);
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Conexiones</h1>
          <p className="text-sm text-gray-500 mt-1">Firewalls Sophos registrados para auditoría</p>
        </div>
        <button className="btn-primary" onClick={() => setModal("create")}>
          <Plus className="w-4 h-4" /> Nueva conexión
        </button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 mb-4">
          <AlertCircle className="w-5 h-5 flex-shrink-0" /><span className="text-sm">{error}</span>
        </div>
      )}

      {loading && <div className="flex items-center justify-center py-20 text-gray-400"><Loader2 className="w-8 h-8 animate-spin" /></div>}

      {!loading && connections.length === 0 && !error && (
        <div className="card text-center py-16 text-gray-400">
          <p className="text-lg font-medium mb-2">Sin conexiones registradas</p>
          <p className="text-sm">Crea la primera conexión para comenzar a auditar firewalls.</p>
        </div>
      )}

      {!loading && connections.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {connections.map((conn) => {
            const tr = testResults[conn.id];
            return (
              <div key={conn.id} className="card flex flex-col gap-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <StatusDot active={conn.is_active} />
                    <h2 className="font-semibold text-gray-900 truncate">{conn.name}</h2>
                  </div>
                  <div className="flex gap-1">
                    <button className="p-1.5 text-gray-400 hover:text-blue-600 transition-colors" onClick={() => setModal(conn)} title="Editar">
                      <Pencil className="w-4 h-4" />
                    </button>
                    <button className="p-1.5 text-gray-400 hover:text-red-600 transition-colors" title="Eliminar"
                      disabled={deletingId === conn.id}
                      onClick={() => setConfirmDelete({ id: conn.id, name: conn.name })}>
                      {deletingId === conn.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="text-sm text-gray-600 space-y-1">
                  <p><span className="font-medium">Host:</span> {conn.host}:{conn.port}</p>
                  <p><span className="font-medium">Usuario:</span> {conn.username}</p>
                  <p><span className="font-medium">SSL:</span> {conn.verify_ssl ? "Sí" : "No"}</p>
                </div>

                {tr && (
                  <div className={`flex items-center gap-2 text-xs p-2 rounded-lg ${tr.success ? "bg-green-50 text-green-700" : "bg-red-50 text-red-700"}`}>
                    {tr.success ? <Wifi className="w-3.5 h-3.5 flex-shrink-0" /> : <WifiOff className="w-3.5 h-3.5 flex-shrink-0" />}
                    <span>{tr.message}</span>
                  </div>
                )}

                <div className="flex gap-2 mt-auto pt-2 border-t border-gray-100 flex-wrap">
                  <button className="btn-secondary text-xs py-1.5 px-3 flex-1" onClick={() => handleTest(conn.id)} disabled={testingId === conn.id}>
                    {testingId === conn.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Wifi className="w-3.5 h-3.5" />}
                    Probar
                  </button>
                  <button className="btn-secondary text-xs py-1.5 px-3 flex-1" onClick={() => navigate(`/query/${conn.id}`)}>
                    <Database className="w-3.5 h-3.5" /> Obtener Info
                  </button>
                  <button className="btn-primary text-xs py-1.5 px-3 flex-1" onClick={() => navigate(`/audit/${conn.id}`)}>
                    <Play className="w-3.5 h-3.5" /> Auditar
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Modales */}
      {modal === "create" && (
        <Modal title="Nueva conexión" onClose={() => setModal(null)}>
          <ConnectionForm onSave={handleCreate} onCancel={() => setModal(null)} />
        </Modal>
      )}
      {modal && modal !== "create" && (
        <Modal title={`Editar: ${modal.name}`} onClose={() => setModal(null)}>
          <ConnectionForm initial={modal} onSave={handleUpdate} onCancel={() => setModal(null)} />
        </Modal>
      )}
      {confirmDelete && (
        <ConfirmModal
          title="Eliminar conexión"
          message={`¿Estás seguro de eliminar "${confirmDelete.name}"? Se eliminará también todo el historial de auditorías asociado. Esta acción no se puede deshacer.`}
          confirmLabel="Sí, eliminar"
          onConfirm={handleDeleteConfirmed}
          onCancel={() => setConfirmDelete(null)}
        />
      )}
    </div>
  );
}
