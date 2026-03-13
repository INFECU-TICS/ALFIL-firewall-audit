import Modal from "./Modal";
import { AlertTriangle } from "lucide-react";

export default function ConfirmModal({ title, message, confirmLabel = "Eliminar", onConfirm, onCancel, danger = true }) {
  return (
    <Modal title={title} onClose={onCancel}>
      <div className="flex gap-3 mb-6">
        <AlertTriangle className={`w-6 h-6 flex-shrink-0 mt-0.5 ${danger ? "text-red-500" : "text-yellow-500"}`} />
        <p className="text-sm text-gray-700">{message}</p>
      </div>
      <div className="flex justify-end gap-2">
        <button className="btn-secondary" onClick={onCancel}>Cancelar</button>
        <button className={danger ? "btn-danger" : "btn-primary"} onClick={onConfirm}>
          {confirmLabel}
        </button>
      </div>
    </Modal>
  );
}
