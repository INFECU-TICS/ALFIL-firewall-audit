import { Routes, Route, NavLink } from "react-router-dom";
import { Shield, Server } from "lucide-react";
import ConnectionsPage from "./pages/ConnectionsPage";
import AuditPage from "./pages/AuditPage";

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
          isActive ? "bg-brand-800 text-white" : "text-brand-100 hover:bg-brand-800/60"
        }`
      }
    >
      {children}
    </NavLink>
  );
}

export default function App() {
  return (
    <div className="min-h-screen flex flex-col">
      {/* Navbar */}
      <header className="bg-brand-900 text-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-7 h-7 text-brand-100" />
            <span className="text-xl font-bold tracking-tight">ALFIL</span>
            <span className="text-brand-100 text-sm hidden sm:block">– Firewall Audit</span>
          </div>
          <nav className="flex gap-1 ml-auto">
            <NavItem to="/">
              <span className="flex items-center gap-1"><Server className="w-4 h-4" /> Conexiones</span>
            </NavItem>
          </nav>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 py-6">
        <Routes>
          <Route path="/" element={<ConnectionsPage />} />
          <Route path="/audit/:id" element={<AuditPage />} />
        </Routes>
      </main>

      <footer className="text-center text-xs text-gray-400 py-4">
        ALFIL – Automated Layered Firewall Inspection &amp; Logic
      </footer>
    </div>
  );
}
