FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Servicio MCP remoto (HTTP). No guarda credenciales: cada petición trae el token del agente.
RUN useradd --system --uid 10001 alfil
USER alfil
ENV MCP_TRANSPORT=http MCP_HOST=0.0.0.0 MCP_PORT=8765
EXPOSE 8765
CMD ["python", "-m", "alfil_mcp.server"]
