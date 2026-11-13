# Grabación de la demo de ALFIL

Genera un video de ~3 min con el flujo completo, **usando el producto real** (sin simulaciones de la interfaz):

1. **Web:** registrar una conexión REST, probarla, auditar, leer el reporte (hallazgos con recomendación, Health Check, alcance), ver los exportes PDF/Excel y la topología, permitir cambios del MCP y crear un token para un agente.
2. **Agente:** sesión **real** de opencode usando el MCP (revisión de salud, diagnóstico de un flujo y un cambio propuesto → aprobado por la persona → aplicado y verificado). La salida se reproduce acelerada en una terminal simulada con el texto real capturado.
3. **Trazabilidad:** último uso, permisos y registro de auditoría; revocación del token.

## Requisitos
- Docker, Node 20+, `ffmpeg`, `poppler-utils` (`pdftoppm`), un Chromium/Chrome (`PLAYWRIGHT_CHROME=<ruta al ejecutable>`) y `opencode` con red.
- Un **firewall de laboratorio** v23 con la API REST habilitada (nunca uno de cliente) y su API key en `API_KEY` de un `.env`.
- `npm install` dentro de `docs/demo/`.

## Pasos
```bash
# 1) Stack aislado y vacío (alias fw-demo.lab -> IP del laboratorio; el video no muestra la IP)
printf 'ENCRYPTION_KEY=%s\nDOMAIN=localhost\nDEBUG=false\nMCP_ALLOW_WRITE=true\n' "$(python3 -c 'import secrets;print(secrets.token_hex(32))')" > demo.env
export DEMO_FW_IP=<ip-del-firewall-lab>
docker compose -p alfil-demo --env-file demo.env -f docker-compose.yml -f docs/demo/docker-compose.demo.yml up -d --build

# 2) Segmento web (deja el token del agente en out/token) y sesión del agente
cd docs/demo && mkdir -p out && export PLAYWRIGHT_CHROME=... DEMO_ENV_FILE=../../.env
node seg1.mjs
PROMPTS_JSON='[{"text":"..."},{"text":"...","cont":true}]' node agent.mjs   # prompts usados: ver abajo
node agent_video.mjs && node seg3.mjs

# 3) Unir los tres segmentos
ffmpeg -i out/seg1.webm -i out/seg2.webm -i out/seg3.webm -filter_complex "[0:v]fps=25,scale=1280:720,setsar=1[a];[1:v]fps=25,scale=1280:720,setsar=1[b];[2:v]fps=25,scale=1280:720,setsar=1[c];[a][b][c]concat=n=3:v=1:a=0[v]" -map "[v]" -c:v libx264 -crf 24 -pix_fmt yuv420p -movflags +faststart out/demo.mp4
```
Prompts usados con el agente: revisión de salud del firewall «Firewall Demo»; «¿por qué no pasa TCP/22 desde 8.8.8.8 hacia 172.16.16.20?»; «propón crear un host demo-servidor 192.0.2.80 y NO lo apliques hasta que yo lo apruebe»; y, con `"cont": true` (`opencode run -c`), «lo apruebo, aplícalo».

## Enmascarar datos antes de publicar
El video muestra la configuración real del laboratorio. Antes de publicarlo enmascare lo que identifique el equipo (hostname/serie, direccionamiento privado): `DEMO_MASK='[["V0100\\w+","FW-DEMO-01"],["192\\.168\\.10\\.","198.51.100."]]'` sustituye ese texto en la pantalla (los tokens MCP se enmascaran siempre) y `DEMO_MASK_PDF='V0100\\w+;;192\\.168\\.10\\.'` tapa lo mismo en las imágenes del PDF. Revise el video fotograma a fotograma antes de subirlo.

## Notas y cuidado
- **Datos:** el agente envía al proveedor del modelo lo que devuelven las herramientas (reglas, IP del laboratorio). Use solo un laboratorio, nunca datos de clientes (INF-POL-IA-001).
- **Secretos:** la API key se escribe en un campo protegido y el token se genera al vuelo; al terminar revoque el token y destruya el stack (`docker compose -p alfil-demo down -v`).
- El servicio de opencode (`opencode serve --service`) cachea la configuración y el entorno: `agent.mjs` lo reinicia para que lea el token nuevo.
- Limpieza del laboratorio: el MCP no borra; elimine `demo-servidor` desde la consola o por la API REST.
- El video publicado (`alfil-demo.mp4`, ~8 MB) se grabó con enmascarado de hostname, direccionamiento privado, IP pública y tokens; los `.webm` intermedios y `out/` no se versionan.
