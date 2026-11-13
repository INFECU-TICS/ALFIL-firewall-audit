# ALFIL – Listas de pruebas por módulo

Cada módulo nuevo se define aquí **antes** de implementarlo y se marca al verificarlo. `[x]` = verificado (con la evidencia entre paréntesis); `[ ]` = pendiente; `[~]` = no verificable por ahora (con el motivo).

Convención: las pruebas automáticas usan datos sintéticos (rangos de documentación, nombres de ejemplo). Las pruebas en vivo requieren el firewall de laboratorio y no se ejecutan con datos de clientes.

## C1. `explain_rule_match` (MCP, Troubleshoot)

Consulta: `source_ip`, `destination_ip`, `protocol` (tcp/udp/icmp…), `destination_port`, zonas opcionales. Devuelve la regla que decide, las reglas anteriores que **podrían** aplicar (no se pueden descartar con los datos de la API) y, por cada regla del par de zonas, por qué no coincide.

- [x] Zonas: regla con otras zonas no coincide; `any` y zona presente coinciden. _(test_zonas)_
- [x] Red origen/destino: host único, red CIDR, rango, lista, grupo de hosts, `any`. _(test_redes, 12 casos)_
- [x] FQDN, país y MAC no se pueden evaluar: la regla queda «posible», nunca «coincide». _(test_objetos_no_evaluables_dejan_la_regla_en_posible)_
- [x] Servicios: `any`, TCP puerto exacto, rango de puertos, protocolo distinto, UDP, ICMP/IP por protocolo, grupo de servicios. _(test_servicios, 11 casos)_
- [x] Puerto omitido con regla de puertos específicos: «posible», no «coincide». _(test_puerto_omitido_con_regla_de_puerto_especifico_es_posible)_
- [x] Exclusiones: IP excluida → la regla no coincide. _(test_exclusiones)_
- [x] Regla deshabilitada se ignora. _(test_orden_primera_coincidencia_definitiva_y_posibles_anteriores)_
- [x] Orden: gana la primera coincidencia definitiva; las «posibles» anteriores se reportan; sin coincidencia → descarte implícito (con aviso). _(test_orden_… y test_sin_coincidencia_es_descarte_implicito)_
- [x] Identidad de usuario y horario: la regla queda «posible» con la nota correspondiente. _(test_horario_e_identidad_dejan_la_regla_en_posible_con_nota)_
- [x] `why_not`: motivo por criterio para las reglas del par de zonas. _(test_why_not_explica_el_criterio_que_falla)_
- [x] Entradas inválidas (IP, puerto, protocolo) → error legible. _(test_entradas_invalidas y test_tool_entradas_invalidas_dan_error_legible)_
- [x] Herramienta MCP: zonas deducidas de la topología con conexión de ALFIL; zonas manuales; sin zonas evalúa sin filtrar por zona y lo avisa. _(test_tool_deduce_zonas_de_la_topologia…, test_tool_zonas_manuales_y_sin_topologia, test_sin_zonas_se_avisa)_
- [x] Solo lectura: solo se piden rutas GET del catálogo. _(test_tool_deduce_zonas…: solo GET y todas las rutas están en el catálogo)_
- [x] En vivo contra el firewall de laboratorio (2026-11-13): reglas con grupo de hosts, red, servicio TCP 8443 y zonas; coincide, no coincide por red de origen (`red_origen: no coincide`), no coincide por servicio y descarte implícito (puerto 22 desde WAN). Formas reales confirmadas: `sourceNetworks.ipv4Groups`, `servicesOrGroups.services`, zonas `{zones:[{name}]}`.

## C2. `trace_object_usage` y `find_unused_objects` (MCP, Troubleshoot / Optimizer)

Índice de referencias: recorre reglas de firewall, reglas NAT, grupos de hosts, grupos de servicios y VPN, y registra qué objeto se usa y por quién (y por qué campo). `trace_object_usage(name, kind?)` responde dónde se usa un objeto (directo e indirecto por grupo); `find_unused_objects(kind?)` lista los objetos definidos que nadie referencia.

- [x] Referencias directas en reglas: redes origen/destino, servicios, zonas, exclusiones (se indica el campo). _(test_referencias_de_un_recurso…, test_usos_directos_en_reglas_nat_y_vpn)_
- [x] Referencias en NAT: origen/destino original, origen/destino traducido, servicio, interfaces, regla enlazada. _(test_nat_traducido_servicio_interfaz_y_regla_enlazada)_
- [x] Referencias en VPN (redes protegidas) y en grupos (miembros). _(test_usos_directos_en_reglas_nat_y_vpn (VPN y pertenencia a grupo))_
- [x] Uso indirecto: host dentro de un grupo usado por una regla (y servicio dentro de un grupo de servicios); se indica la cadena. _(test_uso_indirecto_por_grupo_con_cadena_y_anidado)_
- [x] Grupos anidados no entran en bucle (referencia circular). _(test_grupos_circulares_no_entran_en_bucle)_
- [x] Mismo nombre en tipos distintos (p. ej. zona y host): se separan por tipo. _(test_mismo_nombre_en_tipos_distintos_se_separa)_
- [x] Reglas deshabilitadas se marcan como tales y cuentan como uso (con aviso). _(test_reglas_deshabilitadas_cuentan_pero_se_marcan)_
- [x] Objeto inexistente → error con nombres parecidos. _(test_objeto_inexistente_sugiere_nombres_parecidos, test_tools_errores_legibles)_
- [x] `find_unused_objects`: lista solo lo definido sin referencias; excluye objetos internos del sistema; un host usado solo por un grupo sin uso se reporta como «uso solo vía grupo sin uso». _(test_objetos_sin_uso)_
- [x] Filtro por tipo y límite de resultados. _(test_filtro_por_tipo_y_limite)_
- [x] Solo lectura: rutas GET del catálogo. _(test_tools_trace_y_unused_solo_leen_rutas_del_catalogo)_
- [x] En vivo contra el laboratorio (2026-11-13): uso directo de un host por grupo (`sourceNetworks.ipv4Groups`) y de un servicio, objeto sin uso detectado, hosts del sistema solo vía grupo sin uso; objetos de prueba borrados al final.

## C3. `audit_admin_access` (MCP, Optimizer)

Misma lógica que la web en modo REST (`otp_applies_to_admin`, `build_device_access`). Fuentes: `/authentication/users/administrators`, `/authentication/multi-factor-authentication/totp-settings`, `/network/zones`, `/acl-exception-rules/ipv4`.

- [x] MFA efectivo = OTP habilitado + aplicado a `webAdminPortal` + alcance que cubra al usuario o a su grupo; si no, crítico con el motivo. _(test_mfa_deshabilitado…, test_otp_no_aplicado…, test_alcance_por_usuario_y_grupo)_
- [x] Se ignoran grupos y pseudo-usuarios sin perfil de administración. _(test_mfa_efectivo_sin_hallazgo_y_se_ignoran_cuentas_sin_perfil)_
- [x] Administrador sin restricción de red de origen → informativo. _(test_admin_desde_cualquier_red_es_informativo)_
- [x] HTTPS/SSH en una zona WAN → crítico; en LAN/DMZ no. Servicios de usuario en WAN → informativo. _(test_zona_wan…, test_servicios_de_usuario_en_wan…)_
- [x] Regla de excepción desde WAN: origen «any» → crítico; origen acotado → advertencia; acción distinta de accept, otra zona o servicios no administrativos → sin hallazgo. _(test_regla_de_excepcion_wan…)_
- [x] Sin datos no inventa hallazgos. _(test_sin_datos_no_inventa_hallazgos)_
- [x] Solo lectura: rutas GET del catálogo. _(test_tool_lee_solo_rutas_get_del_catalogo)_
- [x] En vivo (2026-11-13): `admin` y `support` sin MFA (OTP deshabilitado) = los mismos 2 críticos de la auditoría REST; ninguna zona WAN expone administración; con una regla de excepción temporal WAN→https acotada a un host, advertencia con el nombre de la regla (borrada después). Forma real confirmada: `sourceZone`, `sourceNetworks.ipv4Addresses`, `services:[{name}]`.
- [~] Regla de excepción con origen «any» y zona WAN con https/ssh habilitado no se probaron en vivo (exponerían el lab a Internet); solo con tests.

## C4. `audit_network_config` (MCP, Optimizer)

Fuentes: `/nat/rules/ipv4`, `/firewall/rules/ipv4`, `/network/interfaces/network-interfaces`, `/network/zones`, `/notification/notifications`. **NTP/hora:** se buscó en la spec (`ntp`, `time`, `timezone`) y no existe ruta en la API v1; la herramienta lo declara en `limits`.

- [x] DNAT (con `translatedDestination`) desde cualquier origen por interfaz WAN o «any» → advertencia; por interfaz LAN, origen acotado o SNAT/masquerade → sin hallazgo. _(test_dnat_…, test_snat_masquerade_no_es_dnat)_
- [x] Regla NAT enlazada a una regla de firewall inexistente → advertencia; deshabilitada → informativo. _(test_regla_enlazada_inexistente_y_deshabilitada)_
- [x] NAT deshabilitado → informativo (no se evalúa más). _(test_nat_deshabilitado…)_
- [x] Interfaz física habilitada sin zona → informativo; deshabilitadas y VLAN no. _(test_interfaz_habilitada_sin_zona)_
- [x] Sin correo ni SNMP → advertencia; con canal activo pero eventos de administración sin notificar → advertencia. _(test_sin_canales…, test_eventos_de_admin…)_
- [x] Orden por severidad y conteo; solo rutas GET del catálogo. _(test_orden…, test_tool_solo_lee_rutas_get_del_catalogo)_
- [x] En vivo (2026-11-13): `NOTIF_NONE` (igual que la auditoría web) y `PortC`/`PortD` sin zona (coincide con la topología); las 2 reglas NAT automáticas (masquerade) sin hallazgos.
- [~] DNAT real, regla NAT enlazada rota y notificaciones con canal activo no se probaron en vivo (habría que crear NAT de prueba); solo con tests.

## C5. Prompts MCP (`revision_de_salud`, `por_que_no_pasa_este_trafico`)

- [x] Están registrados y son exactamente esos dos. _(test_prompts_registrados)_
- [x] Cada herramienta que nombran existe en el servidor (evita instrucciones a herramientas inexistentes tras un renombre). _(test_los_prompts_solo_nombran_herramientas_existentes)_
- [x] Los argumentos (IPs, protocolo, puerto, conexión) llegan al texto. _(test_argumentos_del_diagnostico)_
- [x] En vivo: `prompts/list` y `prompts/get` por el servicio remoto con cliente MCP real.
- [~] Que un cliente (opencode, Claude Code…) los muestre como comando/prompt no se probó; cada agente los expone distinto.

## C6. `get_vendor_health_check` (MCP)

Fuente: `/firewall-health-check/policies` (31 políticas en el lab; la ruta no pagina).

- [x] El estado manual (`overriddenStatus`) sustituye al calculado. _(test_estado_manual_tiene_prioridad, test_politica_sobrescrita_se_marca)_
- [x] Conteo por estado y por severidad; no conformes ordenadas de mayor a menor severidad y por módulo. _(test_resumen_cuenta_y_ordena_por_severidad)_
- [x] Filtros: incluir conformes, severidad, límite (`matching` frente a `listed`). _(test_filtros_incluir_conformes_severidad_y_limite)_
- [x] Solo lectura: ruta GET del catálogo. _(test_tool_solo_lee_ruta_del_catalogo)_
- [x] En vivo (2026-11-13): 31 políticas, 22 no conformes (11 high, 9 medium, 2 low), coincide con el `summary` del equipo.

## D1. Fase 2 del MCP: cambios con confirmación

Lista blanca: crear regla, habilitar/deshabilitar, mover, crear host, crear servicio (sin borrados ni ediciones libres). Código: `services/mcp_changes.py`, `routers/mcp.py`, herramientas en `server.py`.

- [x] Validación: nombres, acción, zonas/redes/servicios existentes (con sugerencia), posiciones, IP/CIDR, puertos; acción fuera de la lista blanca → rechazo. _(tests/test_mcp_changes.py, 22 tests)_
- [x] Seguridad: regla accept Any→Any bloqueada; las reglas nacen deshabilitadas; advertencias al habilitar/mover. _(test_regla_any_any…, test_crear_regla_*)_
- [x] Tres llaves (servidor, token, conexión) y registro de los rechazos. _(test_las_tres_llaves)_
- [x] Confirmación explícita; solo el token que propuso puede aplicar; no se aplica dos veces; caducidad. _(test_sin_confirmacion…, test_otro_token…, test_propuesta_caducada)_
- [x] Detección de cambios intermedios y copia previa obligatoria (sin ella no se escribe). _(test_si_el_equipo_cambio…, test_sin_copia_previa…)_
- [x] Timeout: se consulta el estado antes de concluir (aplicado / no aplicado / sin confirmar). _(test_timeout_*, test_verificar_aplicado…)_
- [x] El cliente real solo escribe POST/PATCH. _(test_cliente_real_solo_escribe_post_y_patch)_
- [x] Herramientas MCP: anotaciones (propose = no destructiva, apply = destructiva), `apply_change` exige `confirm`, no hay herramientas de borrado, sin ALFIL/modo directo no hay cambios. _(alfil-mcp/tests/test_write_tools.py)_
- [x] **En vivo (lab, 2026-11-13):** crear host y servicio, crear regla drop (deshabilitada, arriba), `explain_rule_match` sin efecto → habilitar → la regla decide → deshabilitar → mover abajo/arriba; todas verificadas por ALFIL; rechazos reales (Any→Any, nombre inválido, sin confirm, token de solo lectura, «ya está última»). Todo borrado al final (por REST directo, el MCP no borra).
- **Hallazgo en vivo:** la API de mover solo acepta `before`/`after` («allowed values are [after before]»); `top`/`bottom` se traducen a «antes de la primera»/«después de la última». La creación sí acepta `top`/`bottom`.
- [~] No probado en vivo: timeout real de escritura, cambio intermedio real y propuesta caducada (solo con tests), ni la UI de los interruptores y el registro (solo compila).

