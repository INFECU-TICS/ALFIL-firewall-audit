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
- [~] En vivo contra el firewall de laboratorio (falta el host del laboratorio en el entorno).
