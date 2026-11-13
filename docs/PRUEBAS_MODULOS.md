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
