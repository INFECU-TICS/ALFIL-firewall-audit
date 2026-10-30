"""Validación en LABORATORIO de audit_firewall: crea reglas ALFIL-TEST-*, audita y las borra.

ESCRIBE en el firewall (POST/DELETE). Solo para el equipo de pruebas.
Requiere ALFIL_LAB_WRITE=yes además de SFOS_HOST / SFOS_TOKEN (o SFOS_ENV_FILE). Cada POST/DELETE tarda ~20 s.
Crea la regla Any→Any al final y la borra primero para minimizar exposición; la limpieza es por prefijo.
Uso: ALFIL_LAB_WRITE=yes SFOS_HOST=<ip> SFOS_VERIFY_SSL=false SFOS_ENV_FILE=../.env python scripts/lab_validate.py
"""
import os
import sys

if os.environ.get("ALFIL_LAB_WRITE") != "yes":
    sys.exit("Este script escribe en el firewall. Define ALFIL_LAB_WRITE=yes para continuar (solo laboratorio).")
import asyncio
import json
import httpx
from alfil_mcp import server
from alfil_mcp.config import Settings

st = Settings.from_env()
ANY = {"any": True}
def z(*n): return {"zones": [{"name": x} for x in n]}
def svc(*n): return {"services": [{"name": x} for x in n], "serviceGroups": []}
BASE = dict(ruleType="firewall", position="bottom", description="ALFIL-MCP lab validation - borrar")
RULES = [
  dict(name="ALFIL-TEST-web-a", enabled=True, action="accept", logTraffic=True, sourceZones=z("LAN"), destinationZones=z("WAN"),
       sourceNetworks=ANY, destinationNetworks=ANY, servicesOrGroups=svc("HTTPS")),
  dict(name="ALFIL-TEST-web-b-dup", enabled=True, action="accept", logTraffic=True, sourceZones=z("LAN"), destinationZones=z("WAN"),
       sourceNetworks=ANY, destinationNetworks=ANY, servicesOrGroups=svc("HTTPS")),
  dict(name="ALFIL-TEST-nolog", enabled=True, action="accept", logTraffic=False, sourceZones=z("LAN"), destinationZones=z("DMZ"),
       sourceNetworks=ANY, destinationNetworks=ANY, servicesOrGroups=svc("DNS")),
  dict(name="ALFIL-TEST-disabled", enabled=False, action="drop", logTraffic=True, sourceZones=z("WiFi"), destinationZones=z("LAN"),
       sourceNetworks=ANY, destinationNetworks=ANY, servicesOrGroups=svc("DNS")),
  dict(name="ALFIL-TEST-anyany", enabled=True, action="accept", logTraffic=True, sourceZones=ANY, destinationZones=ANY,
       sourceNetworks=ANY, destinationNetworks=ANY, servicesOrGroups=ANY),
]
H = {"Authorization": f"Bearer {st.token}", "Accept": "application/json"}

async def main():
    created = []
    async with httpx.AsyncClient(base_url=st.base_url, headers=H, verify=st.verify_ssl, timeout=180) as w:
        try:
            for r in RULES:
                resp = await w.post("firewall/rules/ipv4", json={**BASE, **r})
                print(f"POST {r['name']}: {resp.status_code}", "" if resp.status_code < 300 else resp.text[:300])
                if resp.status_code < 300: created.append(r["name"])
            # servicesOrGroups any: ¿cómo lo representa el equipo?
            got = (await w.get("firewall/rules/ipv4/ALFIL-TEST-anyany"))
            if got.status_code == 200: print("any-any servicesOrGroups ->", json.dumps(got.json().get("servicesOrGroups")))
            audit = await server.audit_firewall()
            print("\nAUDIT score:", audit["score"], "counts:", audit["counts"], "total:", audit["totalRules"])
            for f in audit["findings"]: print(" ", f["code"], "|", f["rule"], "|", f.get("duplicateOf", ""))
            lst = await server.list_firewall_rules(only_enabled=True)
            print("list_firewall_rules(only_enabled) ->", len(lst), "reglas")
        finally:
            # limpieza por prefijo (robusta ante timeouts); anyany primero para minimizar exposición
            lst = (await w.get("firewall/rules/ipv4", params={"pageSize": 100})).json()["items"]
            names = sorted((x["name"] for x in lst if x["name"].startswith("ALFIL-TEST-")), key=lambda n: n != "ALFIL-TEST-anyany")
            for n in names:
                d = await w.delete(f"firewall/rules/ipv4/{n}")
                print(f"DELETE {n}: {d.status_code}")
            left = [x["name"] for x in (await w.get("firewall/rules/ipv4", params={"pageSize": 100})).json()["items"]]
            print("reglas finales:", left)
asyncio.run(main())
