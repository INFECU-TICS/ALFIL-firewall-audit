import fs from "fs";
import { newSession, caption, click, sleep, card } from "./lib.mjs";
const WEB = "http://localhost:8090", out = "out";
const s = await newSession(out, "seg3");
const { page } = s;
page.on("dialog", (d) => d.accept());
try {
  await page.goto(WEB); await sleep(1800);
  await caption(page, "8 · Trazabilidad de lo que hace el agente", "Último uso, permisos del token y registro de auditoría de cada cambio.");
  await sleep(3200);
  await click(page, page.getByText(/Registro de auditoría de cambios/));
  await sleep(500);
  await page.mouse.wheel(0, 120);
  await caption(page, "Quién propuso, quién aplicó y qué cambió", "Cada propuesta, rechazo y aplicación queda registrada con la carga enviada y la copia previa.");
  await sleep(6000); await page.screenshot({ path: `${out}/s3_audit.png` });
  await page.mouse.wheel(0, -400); await sleep(800);
  await caption(page, "9 · Revocar el acceso del agente", "Un clic: el token deja de funcionar (el servicio MCP lo aplica en unos 30 s).");
  await sleep(2500);
  await click(page, page.getByTitle("Revocar token"));
  await sleep(2500); await page.screenshot({ path: `${out}/s3_revoked.png` });
  await caption(page, "Token revocado", "Tokens activos: 0");
  await sleep(3000);
  await card(page, "Resumen", "Registrar · Auditar · Exportar · Topología · Conectar un agente · Cambios con confirmación y auditoría<br><br><span style='font-size:18px;opacity:.7'>Los reportes deben ser revisados por una persona antes de entregarse a un cliente.</span>", 6000);
} catch (e) { await page.screenshot({ path: `${out}/s3_error.png` }).catch(() => {}); console.error("FALLO:", e.message.split("\n")[0]); }
console.log(await s.close());
