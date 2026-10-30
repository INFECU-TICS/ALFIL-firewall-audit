# Inventario API – Sophos Firewall Configuration API v1 (v23)

> Generado desde `alfil-mcp/spec/openapi.yaml`, spec OpenAPI 3.0.0 v1.0.0 extraída del firewall v23 activo (guía de API integrada). **No editar a mano**: regenerar con `alfil-mcp/scripts/gen_inventory.py`.

## Convenciones

- Base URL: `https://<host>:<puerto>/api/firewall-config/v1` (puerto 4444 en el equipo de pruebas).
- Auth: `Authorization: Bearer <api-key>` (esquema `apiKey`, http bearer). Claves en *Administration › API access*.
- Objetos: GET/PATCH/DELETE por `{idOrName}` (nombre único o UUID); en POST el nombre es obligatorio. Formatos `sfos-object-name` (sin comas, `;`, espacios en extremos, nunca un UUID) y `sfos-object-name-or-id`.
- PATCH = JSON Merge Patch (RFC 7396): lo omitido se conserva, `null` elimina; la doc de cada operación puede variar (arrays reemplazados, listas `add`/`remove`). En `oneOf` basta enviar la rama nueva.
- Listados: query `page` (default 1), `pageSize` (default 50, máx 100), `pageTotal` (bool), filtros `nameContains` / `nameNotEquals` (mutuamente excluyentes). Respuesta `{items, pages}`.
- Códigos documentados en listados: 200, 400, 401, 403, 500. Rutas inexistentes en el equipo devuelven 404 HTML.

## Resumen

- Paths: 390 · Operaciones: 708 · Tags: 134
- Por método: DELETE 93, GET 266, PATCH 137, POST 212
- Fase 1 del MCP (solo lectura) usa únicamente las operaciones GET.

## Operaciones por tag

### Active threat response MDR

Operations related to MDR.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/active-threat-response/mdr-threat-feed/settings` | `getMdrThreatFeed` | Retrieve mdr-threat |
| PATCH | `/active-threat-response/mdr-threat-feed/settings` | `patchMdrThreatFeed` | Patch mdr-threat |

### Active threat response Sophos X-Ops

Operations related to Sophos X-Ops threat feeds.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/active-threat-response/sophos-x-ops-threat-feed/settings` | `getSophosXOpsThreatFeedSettings` | List Sophos X-Ops settings |
| PATCH | `/active-threat-response/sophos-x-ops-threat-feed/settings` | `updateSophosXOpsThreatFeedSettings` | Update Sophos X-Ops settings |

### Active threat response third party threat feeds

Add, update, or delete third party threat feeds.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/active-threat-response/thirdparty-threat-feeds` | `getThreatFeed` | Get all threat feeds |
| POST | `/active-threat-response/thirdparty-threat-feeds` | `createThreatFeed` | Create a threat feed |
| POST | `/active-threat-response/thirdparty-threat-feeds/delete` | `bulkDeleteThreatFeed` | Bulk delete threat feeds |
| POST | `/active-threat-response/thirdparty-threat-feeds/test-connection` | `testThreatFeedConnection` | Test connection |
| DELETE | `/active-threat-response/thirdparty-threat-feeds/{idOrName}` | `deleteThreatFeedByKey` | Delete a threat feed |
| GET | `/active-threat-response/thirdparty-threat-feeds/{idOrName}` | `getThreatFeedByIdOrName` | Get a threat feed |
| PATCH | `/active-threat-response/thirdparty-threat-feeds/{idOrName}` | `updateThreatFeed` | Update a threat feed |
| POST | `/active-threat-response/thirdparty-threat-feeds/{idOrName}/synchronize` | `synchronizeThreatFeed` | Synchronize threat feed |

### Active threat response threat exclusions

Operations related to threat exclusions.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/active-threat-response/threat-exclusions` | `getThreatExclusions` | List threat exclusions |
| PATCH | `/active-threat-response/threat-exclusions` | `updateThreatExclusions` | Update threat exclusions |

### Administration API access settings

Manage the Sophos Firewall API access.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/administration/api-settings` | `getAPIConfig` | Get settings |
| PATCH | `/administration/api-settings` | `updateAPIConfig` | Update settings |

### Administration access profiles

Manage access profiles for the firewall web console.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/administration/access/permissions` | `listAccessPermissions` | Get all permissions |
| GET | `/administration/access/profiles` | `listAccessProfiles` | Get all access profiles |
| POST | `/administration/access/profiles` | `createAccessProfile` | Create access profile |
| POST | `/administration/access/profiles/delete` | `bulkDeleteAccessProfiles` | Delete access profile list |
| DELETE | `/administration/access/profiles/{idOrName}` | `deleteAccessProfile` | Delete access profile |
| GET | `/administration/access/profiles/{idOrName}` | `getAccessProfile` | Get access profile |
| PATCH | `/administration/access/profiles/{idOrName}` | `updateAccessProfile` | Update access profile |

### Administration messages

Operations related to administration messages.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/administration/messages` | `getMessages` | Get all messages |
| PATCH | `/administration/messages` | `patchMessages` | Update messages |

### Administration portal settings

Manage the portal settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/administration/portal-settings` | `getPortalSettings` | Get portal settings |
| PATCH | `/administration/portal-settings` | `updatePortalSettings` | Update portal settings |

### Administration schedules

Operations related to schedules.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/administration/schedules` | `listSchedules` | Get all schedules |
| POST | `/administration/schedules` | `createSchedule` | Create a schedule |
| POST | `/administration/schedules/delete` | `bulkDeleteSchedules` | Bulk delete schedules |
| DELETE | `/administration/schedules/{idOrName}` | `deleteSchedule` | Delete a schedule |
| GET | `/administration/schedules/{idOrName}` | `getSchedule` | Get a schedule |
| PATCH | `/administration/schedules/{idOrName}` | `updateSchedule` | Update a schedule |

### Administration system settings

Manage system settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/administration/system-settings` | `getSystemSettings` | Get system settings |
| PATCH | `/administration/system-settings` | `updateSystemSettings` | Update system settings |

### Application attributes

List and view application attribute types and values.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/application/attributes` | `getApplicationAttributes` | List app attributes |
| GET | `/application/attributes/{name}` | `getApplicationAttribute` | Get application attribute |

### Application filter categories

Operations related to application filter categories.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/application/categories` | `listAppFilterCategories` | List categories |
| GET | `/application/categories/{name}` | `getAppFilterCategory` | Get category |
| PATCH | `/application/categories/{name}` | `updateAppFilterCategory` | Update category |

### Application filter policies

Add, update, view, or delete application filter policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/application/policies` | `getAllApplicationFilterPolicies` | List app filter policies |
| POST | `/application/policies` | `createApplicationFilterPolicy` | Create app filter policy |
| POST | `/application/policies/delete` | `bulkDeleteApplicationFilterPolicies` | Bulk delete app policies |
| DELETE | `/application/policies/{idOrName}` | `deleteApplicationFilterPolicy` | Delete app filter policy |
| GET | `/application/policies/{idOrName}` | `getApplicationFilterPolicy` | Get app filter policy |
| PATCH | `/application/policies/{idOrName}` | `updateApplicationFilterPolicy` | Update app filter policy |

### Application objects

Manage application objects.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/application/objects` | `listApplicationObjects` | List Application Objects |
| POST | `/application/objects` | `createApplicationObject` | Create Application Object |
| POST | `/application/objects/delete` | `bulkDeleteApplicationObjects` | Delete Application Objects |
| DELETE | `/application/objects/{idOrName}` | `deleteApplicationObject` | Delete Application Object |
| GET | `/application/objects/{idOrName}` | `getApplicationObject` | Get Application Object |
| PATCH | `/application/objects/{idOrName}` | `updateApplicationObject` | Update Application Object |

### Applications

Get applications or update attributes.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/application/apps` | `listApplications` | List applications |
| GET | `/application/apps/{name}` | `getApplication` | Get application |
| PATCH | `/application/apps/{name}` | `updateApplication` | Update app attributes |

### Authentication SMS gateway settings

Operations related to guest user SMS gateway settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/guest-user-settings/sms-gateways` | `getSmsGateways` | Get all SMS gateways |
| POST | `/authentication/guest-user-settings/sms-gateways` | `createSmsGateway` | Create an SMS gateway |
| POST | `/authentication/guest-user-settings/sms-gateways/delete` | `bulkDeleteSmsGateways` | Bulk delete SMS gateways |
| POST | `/authentication/guest-user-settings/sms-gateways/test-connection` | `testSmsGatewayConnection` | Test gateway connection |
| DELETE | `/authentication/guest-user-settings/sms-gateways/{idOrName}` | `deleteSmsGateway` | Delete an SMS gateway |
| GET | `/authentication/guest-user-settings/sms-gateways/{idOrName}` | `getSmsGateway` | Get an SMS gateway |
| PATCH | `/authentication/guest-user-settings/sms-gateways/{idOrName}` | `updateSmsGateway` | Update an SMS gateway |

### Authentication STAS VPN source networks

Operations related to transparent authentication suite (STAS) VPN source networks.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/clients/transparent-auth-suite/vpn-source-networks` | `listStasVpnSourceNetworks` | List STAS VPN source networks |
| POST | `/authentication/clients/transparent-auth-suite/vpn-source-networks` | `createStasVpnSourceNetwork` | Create STAS VPN source network |
| DELETE | `/authentication/clients/transparent-auth-suite/vpn-source-networks/{idOrName}` | `deleteStasVpnSourceNetwork` | Delete STAS VPN source network |
| GET | `/authentication/clients/transparent-auth-suite/vpn-source-networks/{idOrName}` | `getStasVpnSourceNetwork` | Get STAS VPN source network |

### Authentication STAS collectors

Operations related to transparent authentication suite (STAS) collectors.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/clients/transparent-auth-suite/collectors` | `listStasCollectors` | List STAS collectors |
| POST | `/authentication/clients/transparent-auth-suite/collectors` | `createStasCollector` | Create STAS collector |
| DELETE | `/authentication/clients/transparent-auth-suite/collectors/{idOrName}` | `deleteStasCollector` | Delete STAS collector |
| GET | `/authentication/clients/transparent-auth-suite/collectors/{idOrName}` | `getStasCollector` | Get STAS collector |

### Authentication STAS settings

Operations related to transparent authentication suite (STAS) settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/clients/transparent-auth-suite/settings` | `getStasSettings` | Get STAS settings |
| PATCH | `/authentication/clients/transparent-auth-suite/settings` | `updateStasSettings` | Update STAS settings |

### Authentication TOTP settings

Operations related to TOTP settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/multi-factor-authentication/totp-settings` | `getOtpSettings` | Retrieve OTP settings |
| PATCH | `/authentication/multi-factor-authentication/totp-settings` | `updateOtpSettings` | Update OTP settings |

### Authentication TOTP tokens

Manage TOTP tokens for multi-factor authentication.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/multi-factor-authentication/totp-tokens` | `listTotpTokens` | List TOTP tokens |
| GET | `/authentication/multi-factor-authentication/totp-tokens/hardware-tokens` | `listHardwareTotpTokens` | List hardware TOTP tokens |
| POST | `/authentication/multi-factor-authentication/totp-tokens/hardware-tokens` | `createHardwareTotpToken` | Create hardware TOTP token |
| POST | `/authentication/multi-factor-authentication/totp-tokens/hardware-tokens/delete` | `bulkDeleteHardwareTotpTokens` | Delete hardware TOTP tokens |
| DELETE | `/authentication/multi-factor-authentication/totp-tokens/hardware-tokens/{idOrName}` | `deleteHardwareTotpToken` | Delete hardware TOTP token |
| GET | `/authentication/multi-factor-authentication/totp-tokens/hardware-tokens/{idOrName}` | `getHardwareTotpToken` | Get hardware TOTP token |
| PATCH | `/authentication/multi-factor-authentication/totp-tokens/hardware-tokens/{idOrName}` | `updateHardwareTotpToken` | Update hardware TOTP token |
| GET | `/authentication/multi-factor-authentication/totp-tokens/software-tokens` | `listSoftwareTotpTokens` | List software TOTP tokens |

### Authentication access time profiles

Operations related to access time profile settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/policies/access-times` | `getAccessTimeProfile` | Get access time profiles |
| POST | `/authentication/policies/access-times` | `createAccessTimeProfile` | Create access time profile |
| POST | `/authentication/policies/access-times/delete` | `deleteAccessTimeProfiles` | Bulk delete access time |
| DELETE | `/authentication/policies/access-times/{idOrName}` | `deleteAccessTimeProfileById` | Delete access time profile |
| GET | `/authentication/policies/access-times/{idOrName}` | `getAccessTimeProfileById` | Get an access time profile |
| PATCH | `/authentication/policies/access-times/{idOrName}` | `updateAccessTimeProfile` | Update access time profile |

### Authentication admin user password

Manage the administrator password.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| POST | `/authentication/admin-user/password` | `updateAdminUserPassword` | Update password |

### Authentication captive portal appearance

View and update captive portal appearance settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/captive-portal/appearance` | `getCaptivePortalAppearance` | Get portal appearance |
| PATCH | `/authentication/captive-portal/appearance` | `updateCaptivePortalAppearance` | Update portal appearance |

### Authentication chromebook SSO settings

Operations related to chromebook SSO settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/services/chromebook-sso` | `getChromebookSsoSettings` | Get Chromebook SSO settings |
| PATCH | `/authentication/services/chromebook-sso` | `updateChromebookSsoSettings` | Update Chromebook SSO settings |

### Authentication global user session settings

Manage global user session settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/clients/global-settings` | `getGlobalSettings` | Get user session settings |
| PATCH | `/authentication/clients/global-settings` | `updateGlobalSettings` | Update user session settings |

### Authentication live users

Operations related to connected live user sessions.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/live-users` | `getLiveUsers` | List live user sessions |
| POST | `/authentication/live-users/disconnect` | `disconnectLiveUser` | Disconnect a live user session |

### Authentication login security settings

View and update login security settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/login/security-settings` | `getLoginSecuritySettings` | Get login security settings |
| PATCH | `/authentication/login/security-settings` | `updateLoginSecuritySettings` | Update login security settings |

### Authentication network traffic quotas

Operations related to network traffic quotas.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/policies/network-traffic-quotas` | `getNetworkTrafficQuotas` | Get all traffic quotas |
| POST | `/authentication/policies/network-traffic-quotas` | `createNetworkTrafficQuota` | Create a traffic quota |
| POST | `/authentication/policies/network-traffic-quotas/delete` | `deleteNetworkTrafficQuotas` | Bulk delete traffic quotas |
| DELETE | `/authentication/policies/network-traffic-quotas/{idOrName}` | `deleteNetworkTrafficQuotaById` | Delete a traffic quota |
| GET | `/authentication/policies/network-traffic-quotas/{idOrName}` | `getNetworkTrafficQuotaById` | Get a traffic quota |
| PATCH | `/authentication/policies/network-traffic-quotas/{idOrName}` | `updateNetworkTrafficQuota` | Update a traffic quota |

### Authentication network user login and logout

Sign network users in or out of the appliance.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| POST | `/authentication/users/network-users/login` | `networkUserLiveLogin` | Network user login |
| POST | `/authentication/users/network-users/logout` | `networkUserLiveLogout` | Network user logout |

### Authentication password complexity settings

Operations related to password complexity settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/password-complexity/administrative-users` | `getAdminPasswordComplexitySettings` | Get admin settings |
| PATCH | `/authentication/password-complexity/administrative-users` | `updateAdminPasswordComplexitySettings` | Update admin settings |
| GET | `/authentication/password-complexity/network-users` | `getNetworkUserPasswordComplexitySettings` | Get network settings |
| PATCH | `/authentication/password-complexity/network-users` | `updateNetworkUserPasswordComplexitySettings` | Update network settings |

### Authentication radius accounting SSO settings

Operations related to radius accounting SSO settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/services/radius-accounting-sso` | `listRadiusAccountingClients` | List accounting clients |
| POST | `/authentication/services/radius-accounting-sso` | `createRadiusAccountingClient` | Create accounting client |
| POST | `/authentication/services/radius-accounting-sso/delete` | `bulkDeleteRadiusAccountingClients` | Bulk delete accounting clients |
| DELETE | `/authentication/services/radius-accounting-sso/{idOrName}` | `deleteRadiusAccountingClient` | Delete accounting client |
| GET | `/authentication/services/radius-accounting-sso/{idOrName}` | `getRadiusAccountingClient` | Get accounting client |
| PATCH | `/authentication/services/radius-accounting-sso/{idOrName}` | `updateRadiusAccountingClient` | Update accounting client |

### Authentication servers

Operations related to authentication servers.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/servers` | `getAuthenticationServers` | Get Auth servers |
| GET | `/authentication/servers/active-directory` | `getActiveDirectorySettings` | Get AD servers |
| POST | `/authentication/servers/active-directory` | `createActiveDirectorySettings` | Create an AD server |
| POST | `/authentication/servers/active-directory/delete` | `bulkDeleteActiveDirectorySettings` | Delete AD servers |
| POST | `/authentication/servers/active-directory/test-connection` | `testActiveDirectoryConnection` | Test AD connection |
| DELETE | `/authentication/servers/active-directory/{idOrName}` | `deleteActiveDirectorySettingsByIdOrName` | Delete an AD server |
| GET | `/authentication/servers/active-directory/{idOrName}` | `getActiveDirectorySettingsByIdOrName` | Get an AD server |
| PATCH | `/authentication/servers/active-directory/{idOrName}` | `updateActiveDirectorySettingsByIdOrName` | Update an AD server |
| POST | `/authentication/servers/active-directory/{idOrName}/fetch-groups` | `fetchActiveDirectoryGroups` | Fetch AD groups |
| POST | `/authentication/servers/delete` | `deleteAuthenticationServers` | Bulk delete auth servers |
| GET | `/authentication/servers/generic-idp-sso` | `getGenericIdpSsoServers` | Get all IdP servers |
| POST | `/authentication/servers/generic-idp-sso` | `createGenericIdpSsoServer` | Create an IdP server |
| POST | `/authentication/servers/generic-idp-sso/delete` | `bulkDeleteGenericIdpSsoServers` | Bulk delete IdP servers |
| POST | `/authentication/servers/generic-idp-sso/oidc-discovery` | `discoverGenericIdpSsoOidcEndpoints` | Discover OIDC endpoints |
| POST | `/authentication/servers/generic-idp-sso/test-connection` | `testGenericIdpSsoServerConnection` | Test server connection |
| DELETE | `/authentication/servers/generic-idp-sso/{idOrName}` | `deleteGenericIdpSsoServerByIdOrName` | Delete an IdP server |
| GET | `/authentication/servers/generic-idp-sso/{idOrName}` | `getGenericIdpSsoServerByIdOrName` | Get an IdP server |
| PATCH | `/authentication/servers/generic-idp-sso/{idOrName}` | `updateGenericIdpSsoServerByIdOrName` | Update an IdP server |
| POST | `/authentication/servers/generic-idp-sso/{idOrName}/fetch-groups` | `fetchGenericIdpSsoGroupsByIdOrName` | Fetch IdP groups |
| GET | `/authentication/servers/ldap` | `getLDAPSettings` | Get all LDAP servers |
| POST | `/authentication/servers/ldap` | `createLDAPSettings` | Create an LDAP server |
| POST | `/authentication/servers/ldap/delete` | `bulkDeleteLDAPSettings` | Bulk delete LDAP servers |
| POST | `/authentication/servers/ldap/fetch-base-dn` | `fetchLDAPBaseDN` | Fetch Base DN from LDAP |
| POST | `/authentication/servers/ldap/test-connection` | `testLDAPConnection` | Test LDAP connection |
| DELETE | `/authentication/servers/ldap/{idOrName}` | `deleteLDAPSettingsByIdOrName` | Delete an LDAP server |
| GET | `/authentication/servers/ldap/{idOrName}` | `getLDAPSettingsByIdOrName` | Get an LDAP server |
| PATCH | `/authentication/servers/ldap/{idOrName}` | `updateLDAPSettingsByIdOrName` | Update an LDAP server |
| GET | `/authentication/servers/radius` | `getRadiusSettings` | Get all RADIUS servers |
| POST | `/authentication/servers/radius` | `createRadiusSettings` | Create a RADIUS server |
| POST | `/authentication/servers/radius/delete` | `bulkDeleteRadiusSettings` | Bulk delete RADIUS servers |
| POST | `/authentication/servers/radius/test-connection` | `testRadiusConnection` | Test RADIUS connection |
| DELETE | `/authentication/servers/radius/{idOrName}` | `deleteRadiusSettingsByIdOrName` | Delete a RADIUS server |
| GET | `/authentication/servers/radius/{idOrName}` | `getRadiusSettingsByIdOrName` | Get a RADIUS server |
| PATCH | `/authentication/servers/radius/{idOrName}` | `updateRadiusSettingsByIdOrName` | Update a RADIUS server |
| GET | `/authentication/servers/tacacs` | `getTacacsSettings` | Get all TACACS+ servers |
| POST | `/authentication/servers/tacacs` | `createTacacsSettings` | Create a TACACS+ server |
| POST | `/authentication/servers/tacacs/delete` | `bulkDeleteTacacsSettings` | Bulk delete TACACS+ servers |
| POST | `/authentication/servers/tacacs/test-connection` | `testTacacsConnection` | Test TACACS+ connection |
| DELETE | `/authentication/servers/tacacs/{idOrName}` | `deleteTacacsSettingsByIdOrName` | Delete a TACACS+ server |
| GET | `/authentication/servers/tacacs/{idOrName}` | `getTacacsSettingsByIdOrName` | Get a TACACS+ server |
| PATCH | `/authentication/servers/tacacs/{idOrName}` | `updateTacacsSettingsByIdOrName` | Update a TACACS+ server |
| DELETE | `/authentication/servers/{idOrName}` | `deleteAuthenticationServer` | Delete an auth server |

### Authentication servers priority list

Operations related to authentication server priority list settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/server-priority-list/administrative-access` | `getAdministratorAuthMethodSettings` | Get admin settings |
| PATCH | `/authentication/server-priority-list/administrative-access` | `updateAdministratorAuthMethodSettings` | Update admin settings |
| GET | `/authentication/server-priority-list/default` | `getDefaultAuthMethodSettings` | Get default settings |
| PATCH | `/authentication/server-priority-list/default` | `updateDefaultAuthMethodSettings` | Update default settings |
| GET | `/authentication/server-priority-list/user-portal-access` | `getUserPortalAuthMethodSettings` | Get user portal settings |
| PATCH | `/authentication/server-priority-list/user-portal-access` | `updateUserPortalAuthMethodSettings` | Update user portal |
| GET | `/authentication/server-priority-list/vpn-access` | `getVpnAuthMethodSettings` | Get VPN settings |
| PATCH | `/authentication/server-priority-list/vpn-access` | `updateVpnAuthMethodSettings` | Update VPN settings |

### Authentication surfing quota policies

Operations related to surfing quota policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/policies/surfing-quotas` | `listSurfingQuotaPolicies` | List quota policies |
| POST | `/authentication/policies/surfing-quotas` | `createSurfingQuotaPolicy` | Create quota policy |
| POST | `/authentication/policies/surfing-quotas/delete` | `bulkDeleteSurfingQuotaPolicies` | Delete quota policies |
| DELETE | `/authentication/policies/surfing-quotas/{idOrName}` | `deleteSurfingQuotaPolicy` | Delete quota policy |
| GET | `/authentication/policies/surfing-quotas/{idOrName}` | `getSurfingQuotaPolicy` | Get quota policy |
| PATCH | `/authentication/policies/surfing-quotas/{idOrName}` | `updateSurfingQuotaPolicy` | Update quota policy |

### Authentication user groups

Manage authentication user groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/user-groups` | `getUserGroups` | List user groups |
| POST | `/authentication/user-groups` | `createUserGroup` | Create a user group |
| POST | `/authentication/user-groups/delete` | `bulkDeleteUserGroups` | Bulk delete user groups |
| POST | `/authentication/user-groups/set-fallback-group` | `setFallbackUserGroup` | Set fallback user group |
| DELETE | `/authentication/user-groups/{idOrName}` | `deleteUserGroup` | Delete a user group |
| GET | `/authentication/user-groups/{idOrName}` | `getUserGroup` | Get a user group |
| PATCH | `/authentication/user-groups/{idOrName}` | `updateUserGroup` | Update a user group |

### Authentication users

Manage authentication users.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/users` | `getUsers` | List users |
| GET | `/authentication/users/administrators` | `getAdministrators` | List administrators |
| POST | `/authentication/users/administrators` | `createAdministrator` | Create an administrator |
| POST | `/authentication/users/administrators/delete` | `bulkDeleteAdministrators` | Bulk delete administrators |
| DELETE | `/authentication/users/administrators/{idOrName}` | `deleteAdministrator` | Delete an administrator |
| GET | `/authentication/users/administrators/{idOrName}` | `getAdministrator` | Get an administrator |
| PATCH | `/authentication/users/administrators/{idOrName}` | `updateAdministrator` | Update an administrator |
| GET | `/authentication/users/network-users` | `getNetworkUsers` | List network users |
| POST | `/authentication/users/network-users` | `createNetworkUser` | Create a network user |
| POST | `/authentication/users/network-users/delete` | `bulkDeleteNetworkUsers` | Bulk delete network users |
| DELETE | `/authentication/users/network-users/{idOrName}` | `deleteNetworkUser` | Delete a network user |
| GET | `/authentication/users/network-users/{idOrName}` | `getNetworkUser` | Get a network user |
| PATCH | `/authentication/users/network-users/{idOrName}` | `updateNetworkUser` | Update a network user |

### Authentication web authentication settings

Operations related to web authentication settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/authentication/web-settings` | `getWebAuthenticationSettings` | Get web auth settings |
| PATCH | `/authentication/web-settings` | `updateWebAuthenticationSettings` | Update web auth settings |

### Certificate authorities

Operations related to certificate authorities.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/certificate/certificate-authorities` | `listCertificateAuthorities` | List CAs |
| POST | `/certificate/certificate-authorities` | `createCertificateAuthority` | Create CA |
| POST | `/certificate/certificate-authorities/delete` | `bulkDeleteCertificateAuthorities` | Delete CAs |
| DELETE | `/certificate/certificate-authorities/{idOrName}` | `deleteCertificateAuthority` | Delete CA |
| GET | `/certificate/certificate-authorities/{idOrName}` | `getCertificateAuthority` | Get certificate authority |

### Certificate default CA

Operations related to the default certificate authority.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/certificate/certificate-authorities/built-in/default-ca` | `getDefaultCa` | Get a default CA |
| POST | `/certificate/certificate-authorities/built-in/default-ca/regenerate` | `regenerateDefaultCa` | Regenerate a default CA |

### Certificate locally signed certificates

Operations for locally signed certificates.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/certificate/certificates/internal` | `listLocalSignedCertificates` | List certificates |
| POST | `/certificate/certificates/internal` | `createLocalSignedCertificate` | Create certificate |
| POST | `/certificate/certificates/internal/delete` | `bulkDeleteLocalSignedCertificates` | Delete certificate list |
| DELETE | `/certificate/certificates/internal/{idOrName}` | `deleteLocalSignedCertificate` | Delete certificate |
| GET | `/certificate/certificates/internal/{idOrName}` | `getLocalSignedCertificate` | Get certificate |

### Certificate revocation lists

Operations related to certificate revocation lists.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/certificate/certificate-revocation-lists` | `listCertificateRevocationLists` | List CRLs |
| POST | `/certificate/certificate-revocation-lists` | `createCertificateRevocationList` | Create CRL |
| POST | `/certificate/certificate-revocation-lists/delete` | `bulkDeleteCertificateRevocationLists` | Delete CRLs |
| DELETE | `/certificate/certificate-revocation-lists/{idOrName}` | `deleteCertificateRevocationList` | Delete CRL |
| GET | `/certificate/certificate-revocation-lists/{idOrName}` | `getCertificateRevocationList` | Get CRL |

### Certificate signing requests

Operations related to certificate signing requests.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/certificate/certificates/certificate-signing-requests` | `listCertificateSigningRequests` | List CSRs |
| POST | `/certificate/certificates/certificate-signing-requests` | `createCertificateSigningRequest` | Create CSR |
| POST | `/certificate/certificates/certificate-signing-requests/delete` | `bulkDeleteCertificateSigningRequests` | Delete CSR list |
| DELETE | `/certificate/certificates/certificate-signing-requests/{idOrName}` | `deleteCertificateSigningRequest` | Delete CSR |
| GET | `/certificate/certificates/certificate-signing-requests/{idOrName}` | `getCertificateSigningRequest` | Get CSR |

### Certificate uploaded certificates

Operations related to uploaded certificates.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/certificate/certificates/external` | `listUploadedCertificates` | List uploaded certs |
| POST | `/certificate/certificates/external` | `createUploadedCertificate` | Create certificate |
| POST | `/certificate/certificates/external/delete` | `bulkDeleteUploadedCertificates` | Delete certificate list |
| DELETE | `/certificate/certificates/external/{idOrName}` | `deleteUploadedCertificate` | Delete uploaded cert |
| GET | `/certificate/certificates/external/{idOrName}` | `getUploadedCertificate` | Get uploaded cert |

### Certificates

Operations for different certificates.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/certificate/certificates` | `listCertificates` | List certificates |

### DoS attacks

Collects DoS attack state data.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/denial-of-service/attacks/summary` | `getAttacks` | Get attacks data |
| GET | `/denial-of-service/attacks/{floodAttackType}` | `getAttacksByFlood` | Get attacks by flood type |

### DoS policies

Operations related to DoS policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/denial-of-service/policies` | `getAllPolicies` | Returns all policies |
| POST | `/denial-of-service/policies` | `createPolicy` | Creates policy |
| DELETE | `/denial-of-service/policies/{idOrName}` | `deletePolicyByIdOrName` | Delete dos policy |
| GET | `/denial-of-service/policies/{idOrName}` | `getPolicyByIdOrName` | Get dos policy |

### DoS settings

Update and view DoS settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/denial-of-service/settings` | `getDosSettings` | Get DoS settings |
| PATCH | `/denial-of-service/settings` | `updateDosSettings` | Updates DoS settings |

### Firewall NAT rules

Operations related to NAT rules.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/nat/rules/ipv4` | `getAllNatRulesIpv4` | Get all IPv4 rules |
| POST | `/nat/rules/ipv4` | `createNatRuleIpv4` | Create an IPv4 rule |
| POST | `/nat/rules/ipv4/delete` | `bulkDeleteNatRulesIpv4` | Bulk delete IPv4 rules |
| POST | `/nat/rules/ipv4/move` | `moveNatRuleIpv4` | Move an IPv4 rule |
| DELETE | `/nat/rules/ipv4/{idOrName}` | `deleteNatRuleIpv4ByIdOrName` | Delete an IPv4 rule |
| GET | `/nat/rules/ipv4/{idOrName}` | `getNatRuleIpv4ByIdOrName` | Get an IPv4 rule |
| PATCH | `/nat/rules/ipv4/{idOrName}` | `updateNatRuleIpv4ByIdOrName` | Update an IPv4 rule |
| GET | `/nat/rules/ipv6` | `getAllNatRulesIpv6` | Get all IPv6 rules |
| POST | `/nat/rules/ipv6` | `createNatRuleIpv6` | Create an IPv6 rule |
| POST | `/nat/rules/ipv6/delete` | `bulkDeleteNatRulesIpv6` | Bulk delete IPv6 rules |
| POST | `/nat/rules/ipv6/move` | `moveNatRuleIpv6` | Move an IPv6 rule |
| DELETE | `/nat/rules/ipv6/{idOrName}` | `deleteNatRuleIpv6ByIdOrName` | Delete an IPv6 rule |
| GET | `/nat/rules/ipv6/{idOrName}` | `getNatRuleIpv6ByIdOrName` | Get an IPv6 rule |
| PATCH | `/nat/rules/ipv6/{idOrName}` | `updateNatRuleIpv6ByIdOrName` | Update an IPv6 rule |

### Firewall health check

Operations related to firewall health check.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/firewall-health-check/policies` | `getHealthCheckPolicyList` | Policy list |
| GET | `/firewall-health-check/policies/summary` | `getHealthCheckSummary` | Policies summary |
| PATCH | `/firewall-health-check/policies/{id}` | `updateHealthCheckPolicyStatus` | Update policy status |

### Firewall local service ACL exception rules

Operations related to local service ACL exception rules.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/acl-exception-rules/ipv4` | `getAllAclExceptionRulesIpv4` | Get all IPv4 rules |
| POST | `/acl-exception-rules/ipv4` | `createAclExceptionRuleIpv4` | Create an IPv4 rule |
| POST | `/acl-exception-rules/ipv4/delete` | `bulkDeleteAclExceptionRulesIpv4` | Bulk delete IPv4 rules |
| DELETE | `/acl-exception-rules/ipv4/{idOrName}` | `deleteAclExceptionRuleIpv4` | Delete an IPv4 rule |
| GET | `/acl-exception-rules/ipv4/{idOrName}` | `getAclExceptionRuleIpv4` | Get an IPv4 rule |
| PATCH | `/acl-exception-rules/ipv4/{idOrName}` | `updateAclExceptionRuleIpv4` | Update an IPv4 rule |
| GET | `/acl-exception-rules/ipv6` | `getAllAclExceptionRulesIpv6` | Get all IPv6 rules |
| POST | `/acl-exception-rules/ipv6` | `createAclExceptionRuleIpv6` | Create an IPv6 rule |
| POST | `/acl-exception-rules/ipv6/delete` | `bulkDeleteAclExceptionRulesIpv6` | Bulk delete IPv6 rules |
| DELETE | `/acl-exception-rules/ipv6/{idOrName}` | `deleteAclExceptionRuleIpv6` | Delete an IPv6 rule |
| GET | `/acl-exception-rules/ipv6/{idOrName}` | `getAclExceptionRuleIpv6` | Get an IPv6 rule |
| PATCH | `/acl-exception-rules/ipv6/{idOrName}` | `updateAclExceptionRuleIpv6` | Update an IPv6 rule |

### Firewall rules

Operations related to firewall rules.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/firewall/rules/ipv4` | `getAllFirewallRulesIpv4` | Get all IPv4 rules |
| POST | `/firewall/rules/ipv4` | `createFirewallRuleIpv4` | Create IPv4 rule |
| POST | `/firewall/rules/ipv4/delete` | `bulkDeleteFirewallRulesIpv4` | Bulk delete IPv4 rules |
| POST | `/firewall/rules/ipv4/move` | `moveFirewallRuleIpv4` | Move IPv4 rule |
| DELETE | `/firewall/rules/ipv4/{idOrName}` | `deleteFirewallRuleIpv4` | Delete IPv4 rule |
| GET | `/firewall/rules/ipv4/{idOrName}` | `getFirewallRuleIpv4` | Get IPv4 rule |
| PATCH | `/firewall/rules/ipv4/{idOrName}` | `updateFirewallRuleIpv4` | Update IPv4 rule |
| GET | `/firewall/rules/ipv6` | `getAllFirewallRulesIpv6` | Get all IPv6 rules |
| POST | `/firewall/rules/ipv6` | `createFirewallRuleIpv6` | Create IPv6 rule |
| POST | `/firewall/rules/ipv6/delete` | `bulkDeleteFirewallRulesIpv6` | Bulk delete IPv6 rules |
| POST | `/firewall/rules/ipv6/move` | `moveFirewallRuleIpv6` | Move IPv6 rule |
| DELETE | `/firewall/rules/ipv6/{idOrName}` | `deleteFirewallRuleIpv6` | Delete IPv6 rule |
| GET | `/firewall/rules/ipv6/{idOrName}` | `getFirewallRuleIpv6` | Get IPv6 rule |
| PATCH | `/firewall/rules/ipv6/{idOrName}` | `updateFirewallRuleIpv6` | Update IPv6 rule |

### IPS custom signatures

Add, update, view, or delete IPS custom signatures.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/intrusion-prevention/custom-signatures` | `getIpsCustomSignatures` | List IPS custom sigs |
| POST | `/intrusion-prevention/custom-signatures` | `createIpsCustomSignature` | Create IPS custom sig |
| POST | `/intrusion-prevention/custom-signatures/delete` | `bulkDeleteIpsCustomSignatures` | Bulk delete custom sigs |
| DELETE | `/intrusion-prevention/custom-signatures/{idOrName}` | `deleteIpsCustomSignature` | Delete IPS custom sig |
| GET | `/intrusion-prevention/custom-signatures/{idOrName}` | `getIpsCustomSignature` | Get IPS custom sig |
| PATCH | `/intrusion-prevention/custom-signatures/{idOrName}` | `updateIpsCustomSignature` | Update IPS custom sig |

### IPS policies

Add, update, view, or delete IPS policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/intrusion-prevention/policies` | `getIpsPolicies` | Get all IPS policies |
| POST | `/intrusion-prevention/policies` | `createIpsPolicy` | Create an IPS policy |
| POST | `/intrusion-prevention/policies/delete` | `bulkDeleteIpsPolicies` | Bulk delete IPS policies |
| DELETE | `/intrusion-prevention/policies/{idOrName}` | `deleteIpsPolicy` | Delete an IPS policy |
| GET | `/intrusion-prevention/policies/{idOrName}` | `getIpsPolicy` | Get an IPS policy |
| PATCH | `/intrusion-prevention/policies/{idOrName}` | `updateIpsPolicy` | Update an IPS policy |

### IPS settings

Update and view IPS settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/intrusion-prevention/settings` | `getIpsSettings` | Get IPS settings |
| PATCH | `/intrusion-prevention/settings` | `updateIpsSettings` | Update IPS settings |

### IPS signature attributes

List and view IPS signature attribute types and values.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/intrusion-prevention/signature-attributes` | `getIpsSignatureAttributes` | List IPS attributes |
| GET | `/intrusion-prevention/signature-attributes/{name}` | `getIpsSignatureAttribute` | Get IPS attribute |

### IPsec failover groups

Operations related to IPsec failover groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ipsec-vpn/site-to-site/failover-groups` | `getFailovergroups` | Get all failovergroups |
| POST | `/ipsec-vpn/site-to-site/failover-groups` | `createFailovergroup` | Create failovergroup |
| POST | `/ipsec-vpn/site-to-site/failover-groups/delete` | `deleteFailovergroups` | Delete failovergroups |
| DELETE | `/ipsec-vpn/site-to-site/failover-groups/{idOrName}` | `deleteFailovergroup` | Delete failovergroup |
| GET | `/ipsec-vpn/site-to-site/failover-groups/{idOrName}` | `getFailovergroup` | Get IPsec failovergroup |
| PATCH | `/ipsec-vpn/site-to-site/failover-groups/{idOrName}` | `updateFailovergroup` | Update failovergroup |

### IPsec profiles

Operations related to IPsec profiles.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ipsec-vpn/profiles` | `getProfiles` | Get all IPsec profiles |
| POST | `/ipsec-vpn/profiles` | `createProfile` | Create IPsec profile |
| POST | `/ipsec-vpn/profiles/delete` | `deleteProfiles` | Deletes IPsec profiles |
| DELETE | `/ipsec-vpn/profiles/{idOrName}` | `deleteProfile` | Delete profile |
| GET | `/ipsec-vpn/profiles/{idOrName}` | `getProfile` | Get IPsec profile |
| PATCH | `/ipsec-vpn/profiles/{idOrName}` | `updateProfile` | Update profile |

### IPsec remote access VPN settings

Operations related to IPsec remote access VPN settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ipsec-vpn/remote-access/settings` | `getIpsecRemoteAccessVpnSettings` | Get remote access VPN |
| PATCH | `/ipsec-vpn/remote-access/settings` | `updateIpsecRemoteAccessVpnSettings` | Update remote access VPN |

### IPsec site-to-site connections

Operations related to site-to-site IPsec connections.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ipsec-vpn/site-to-site/connections/ipv4` | `listIpsecConnectionsIpv4` | Get all IPv4 connections |
| POST | `/ipsec-vpn/site-to-site/connections/ipv4/delete` | `bulkDeleteIpsecConnectionsIpv4` | Bulk delete IPv4 |
| DELETE | `/ipsec-vpn/site-to-site/connections/ipv4/{idOrName}` | `deleteIpsecConnectionIpv4` | Delete IPv4 connection |
| GET | `/ipsec-vpn/site-to-site/connections/policy-based/ipv4` | `listIpsecPolicyBasedConnectionsIpv4` | Get all IPv4 policy-based |
| POST | `/ipsec-vpn/site-to-site/connections/policy-based/ipv4` | `createPolicyBasedIpsecConnectionIpv4` | Create IPv4 policy-based |
| POST | `/ipsec-vpn/site-to-site/connections/policy-based/ipv4/delete` | `bulkDeletePolicyBasedIpsecConnectionsIpv4` | Bulk delete policy-based |
| DELETE | `/ipsec-vpn/site-to-site/connections/policy-based/ipv4/{idOrName}` | `deletePolicyBasedIpsecConnectionIpv4` | Delete IPv4 policy-based |
| GET | `/ipsec-vpn/site-to-site/connections/policy-based/ipv4/{idOrName}` | `getPolicyBasedIpsecConnectionIpv4` | Get IPv4 policy-based |
| PATCH | `/ipsec-vpn/site-to-site/connections/policy-based/ipv4/{idOrName}` | `updatePolicyBasedIpsecConnectionIpv4` | Update IPv4 policy-based |
| GET | `/ipsec-vpn/site-to-site/connections/route-based/ipv4` | `listIpsecRouteBasedConnectionsIpv4` | Get all IPv4 route-based |
| POST | `/ipsec-vpn/site-to-site/connections/route-based/ipv4` | `createRouteBasedIpsecConnectionIpv4` | Create IPv4 route-based |
| POST | `/ipsec-vpn/site-to-site/connections/route-based/ipv4/delete` | `bulkDeleteRouteBasedIpsecConnectionsIpv4` | Bulk delete route-based |
| DELETE | `/ipsec-vpn/site-to-site/connections/route-based/ipv4/{idOrName}` | `deleteRouteBasedIpsecConnectionIpv4` | Delete IPv4 route-based |
| GET | `/ipsec-vpn/site-to-site/connections/route-based/ipv4/{idOrName}` | `getRouteBasedIpsecConnectionIpv4` | Get IPv4 route-based |
| PATCH | `/ipsec-vpn/site-to-site/connections/route-based/ipv4/{idOrName}` | `updateRouteBasedIpsecConnectionIpv4` | Update IPv4 route-based |

### IPsec site-to-site live connections

Operations related to site-to-site IPsec live connections.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ipsec-vpn/site-to-site/live-connections/ipv4` | `getIpsecSiteToSiteLiveConnectionsIpv4` | Get live connections |

### Log attributes

Read-only catalogs of available log types and log components.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/logging/log-attributes/components` | `getLogAttributeComponents` | Get log components |
| GET | `/logging/log-attributes/types` | `getLogAttributeTypes` | Get log types |

### Log destinations

Local and central reporting destination toggles.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/logging/log-destinations/central-firewall-reporting` | `getCentralFirewallReportingLogComponents` | Get central CFR components |
| PATCH | `/logging/log-destinations/central-firewall-reporting` | `updateCentralFirewallReportingLogComponents` | Update central CFR components |
| GET | `/logging/log-destinations/log-viewer` | `getLogViewerLogComponents` | Get log viewer components |
| PATCH | `/logging/log-destinations/log-viewer` | `updateLogViewerLogComponents` | Update log viewer components |

### Log destinations syslog servers

Syslog server CRUD, bulk delete, and per-server log component configuration.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/logging/log-destinations/syslog-servers` | `getSyslogServers` | List syslog servers |
| POST | `/logging/log-destinations/syslog-servers` | `createSyslogServer` | Create syslog server |
| POST | `/logging/log-destinations/syslog-servers/delete` | `bulkDeleteSyslogServers` | Bulk delete syslog servers |
| DELETE | `/logging/log-destinations/syslog-servers/{idOrName}` | `deleteSyslogServer` | Delete a syslog server |
| GET | `/logging/log-destinations/syslog-servers/{idOrName}` | `getSyslogServer` | Get a syslog server |
| PATCH | `/logging/log-destinations/syslog-servers/{idOrName}` | `updateSyslogServer` | Update a syslog server |
| GET | `/logging/log-destinations/syslog-servers/{idOrName}/logs` | `getSyslogServerLogs` | Get syslog log components |
| PATCH | `/logging/log-destinations/syslog-servers/{idOrName}/logs` | `updateSyslogServerLogs` | Update syslog log components |

### Log settings

Global log type and suppression settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/logging/log-settings` | `getLogSettings` | Get log settings |
| PATCH | `/logging/log-settings` | `updateLogSettings` | Update log settings |

### Malware protection

Operations related to malware protection settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/malware-protection/settings` | `getMalwareProtectionSettings` | Get malware settings |
| PATCH | `/malware-protection/settings` | `updateMalwareProtectionSettings` | Update malware settings |

### Monitoring NetFlow configuration

Configure NetFlow export destinations.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/monitoring/netflow/collectors` | `getNetFlowCollectors` | List NetFlow collectors |
| POST | `/monitoring/netflow/collectors` | `createNetFlowCollector` | Create NetFlow collector |
| POST | `/monitoring/netflow/collectors/delete` | `bulkDeleteNetFlowCollectors` | Bulk delete collectors |
| DELETE | `/monitoring/netflow/collectors/{idOrName}` | `deleteNetFlowCollector` | Delete NetFlow collector |
| GET | `/monitoring/netflow/collectors/{idOrName}` | `getNetFlowCollector` | Get a NetFlow collector |
| PATCH | `/monitoring/netflow/collectors/{idOrName}` | `updateNetFlowCollector` | Update NetFlow collector |

### Monitoring SNMP agent configuration

Configure SNMP agent.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/monitoring/snmp/agent-configuration` | `getSnmpAgentConfiguration` | Get agent conf |
| PATCH | `/monitoring/snmp/agent-configuration` | `updateSnmpAgentConfiguration` | Update agent conf |

### Monitoring SNMP communities

Add, update, view or delete SNMP communities.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/monitoring/snmp/communities` | `getSnmpCommunities` | Returns SNMP communities |
| POST | `/monitoring/snmp/communities` | `createSnmpCommunity` | Creates SNMP community |
| POST | `/monitoring/snmp/communities/delete` | `bulkDeleteSnmpCommunities` | Delete SNMP communities |
| DELETE | `/monitoring/snmp/communities/{idOrName}` | `deleteSnmpCommunity` | Deletes SNMP community |
| GET | `/monitoring/snmp/communities/{idOrName}` | `getSnmpCommunity` | Returns SNMP community |
| PATCH | `/monitoring/snmp/communities/{idOrName}` | `updateSnmpCommunity` | Updates SNMP community |

### Monitoring SNMP users

Add, update, view or delete SNMP users.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/monitoring/snmp/users` | `getSnmpUsers` | Returns SNMP users |
| POST | `/monitoring/snmp/users` | `createSnmpUser` | Creates SNMP user |
| POST | `/monitoring/snmp/users/delete` | `bulkDeleteSnmpUsers` | Delete SNMP users |
| DELETE | `/monitoring/snmp/users/{idOrName}` | `deleteSnmpUser` | Deletes SNMP user |
| GET | `/monitoring/snmp/users/{idOrName}` | `getSnmpUser` | Returns SNMP user |
| PATCH | `/monitoring/snmp/users/{idOrName}` | `updateSnmpUser` | Updates SNMP user |

### Network DHCP relays

Operations related to DHCP relay settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/dhcp/relays/ipv4` | `getAllDhcpRelayIpv4` | Get IPv4 DHCP relays |
| POST | `/network/dhcp/relays/ipv4` | `createDhcpRelayIpv4` | Add IPv4 DHCP relay |
| POST | `/network/dhcp/relays/ipv4/delete` | `deleteDhcpRelaysIpv4` | Delete IPv4 DHCP relays |
| DELETE | `/network/dhcp/relays/ipv4/{idOrName}` | `deleteDhcpRelayByIdIpv4` | Delete IPv4 DHCP Relay |
| GET | `/network/dhcp/relays/ipv4/{idOrName}` | `getDhcpRelayByIdIpv4` | Get IPv4 DHCP relay |
| PATCH | `/network/dhcp/relays/ipv4/{idOrName}` | `updateDhcpRelayByIdIpv4` | Update IPv4 DHCP relay |
| GET | `/network/dhcp/relays/ipv6` | `getAllDhcpRelayIpv6` | Get IPv6 DHCP relays |
| POST | `/network/dhcp/relays/ipv6` | `createDhcpRelayIpv6` | Add IPv6 DHCP relay |
| POST | `/network/dhcp/relays/ipv6/delete` | `deleteDhcpRelaysIpv6` | Delete IPv6 DHCP relays |
| DELETE | `/network/dhcp/relays/ipv6/{idOrName}` | `deleteDhcpRelayByIdIpv6` | Delete IPv6 DHCP Relay |
| GET | `/network/dhcp/relays/ipv6/{idOrName}` | `getDhcpRelayByIdIpv6` | Get IPv6 DHCP relay |
| PATCH | `/network/dhcp/relays/ipv6/{idOrName}` | `updateDhcpRelayByIdIpv6` | Update IPv6 DHCP relay |

### Network DHCP server settings

Operations related to DHCP server settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/dhcp/server/settings/ipv4` | `getDhcpSettings` | Get DHCP settings |
| PATCH | `/network/dhcp/server/settings/ipv4` | `updateDhcpSettings` | Update DHCP settings |

### Network DHCPv4 servers

Operations related to DHCPv4 server settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/dhcp/server/servers/ipv4` | `listDhcpServersIpv4` | List DHCPv4 servers |
| POST | `/network/dhcp/server/servers/ipv4` | `createDhcpServerIpv4` | Create DHCPv4 server |
| POST | `/network/dhcp/server/servers/ipv4/delete` | `bulkDeleteDhcpServersIpv4` | Delete DHCPv4 server list |
| DELETE | `/network/dhcp/server/servers/ipv4/{idOrName}` | `deleteDhcpServerIpv4` | Delete DHCPv4 server |
| GET | `/network/dhcp/server/servers/ipv4/{idOrName}` | `getDhcpServerIpv4` | Get DHCPv4 server |
| PATCH | `/network/dhcp/server/servers/ipv4/{idOrName}` | `updateDhcpServerIpv4` | Update DHCPv4 server |

### Network DHCPv6 servers

Operations related to DHCPv6 server settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/dhcp/server/servers/ipv6` | `listDhcpServersIpv6` | List DHCPv6 servers |
| POST | `/network/dhcp/server/servers/ipv6` | `createDhcpServerIpv6` | Create DHCPv6 server |
| POST | `/network/dhcp/server/servers/ipv6/delete` | `bulkDeleteDhcpServersIpv6` | Delete DHCPv6 server list |
| DELETE | `/network/dhcp/server/servers/ipv6/{idOrName}` | `deleteDhcpServerIpv6` | Delete DHCPv6 server |
| GET | `/network/dhcp/server/servers/ipv6/{idOrName}` | `getDhcpServerIpv6` | Get DHCPv6 server |
| PATCH | `/network/dhcp/server/servers/ipv6/{idOrName}` | `updateDhcpServerIpv6` | Update DHCPv6 server |

### Network DNS host entries

Operations related to DNS host entry.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/dns/host-entries` | `getAllDnsHostEntries` | Get DNS host entries |
| POST | `/network/dns/host-entries` | `createDnsHostEntry` | Add DNS host entry |
| POST | `/network/dns/host-entries/delete` | `deleteDnsHostEntries` | Delete DNS Host Entries |
| DELETE | `/network/dns/host-entries/{idOrName}` | `deleteDnsHostEntryById` | Delete DNS host entry |
| GET | `/network/dns/host-entries/{idOrName}` | `getDnsHostEntryById` | Get DNS host entry |
| PATCH | `/network/dns/host-entries/{idOrName}` | `updateDnsHostEntryById` | Update DNS host entry |

### Network DNS request routes

Operations related to DNS request route.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/dns/request-routes` | `getAllDnsRequestRoutes` | Get DNS request routes |
| POST | `/network/dns/request-routes` | `createDnsRequestRoute` | Add DNS request route |
| POST | `/network/dns/request-routes/delete` | `deleteDnsRequestRoutes` | Delete DNS request routes |
| DELETE | `/network/dns/request-routes/{idOrName}` | `deleteDnsRequestRouteById` | Delete DNS Request Route |
| GET | `/network/dns/request-routes/{idOrName}` | `getDnsRequestRouteById` | Get DNS request route |
| PATCH | `/network/dns/request-routes/{idOrName}` | `updateDnsRequestRouteById` | Update DNS request route |

### Network DNS settings

Update and view DNS settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/dns/protection/status` | `getDnsProtectionStatus` | DNS protection status |
| GET | `/network/dns/settings` | `getDnsSettings` | Get DNS settings |
| PATCH | `/network/dns/settings` | `updateDnsSettings` | Update DNS settings |

### Network address groups FQDN

Manage FQDN groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/address-groups/fqdn` | `getAllFqdnGroups` | Get all FQDN groups |
| POST | `/network/address-groups/fqdn` | `createFqdnGroup` | Create a FQDN group |
| POST | `/network/address-groups/fqdn/delete` | `bulkDeleteFqdnGroups` | Bulk delete groups |
| DELETE | `/network/address-groups/fqdn/{idOrName}` | `deleteFqdnGroupByIdOrName` | Delete an FQDN group |
| GET | `/network/address-groups/fqdn/{idOrName}` | `getFqdnGroupByIdOrName` | Get FQDN group |
| PATCH | `/network/address-groups/fqdn/{idOrName}` | `updateFqdnGroupByIdOrName` | Update an FQDN group |

### Network address groups IPv4

Manage IPv4 address groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/address-groups/ipv4` | `getAllIpv4AddressGroups` | Get IPv4 address groups |
| POST | `/network/address-groups/ipv4` | `createIpv4AddressGroup` | Create an IPv4 group |
| POST | `/network/address-groups/ipv4/delete` | `bulkDeleteIpv4AddressGroups` | Bulk delete IPv4 groups |
| DELETE | `/network/address-groups/ipv4/{idOrName}` | `deleteIpv4AddressGroupByIdOrName` | Delete an IPv4 group |
| GET | `/network/address-groups/ipv4/{idOrName}` | `getIpv4AddressGroupByIdOrName` | Get an IPv4 group |
| PATCH | `/network/address-groups/ipv4/{idOrName}` | `updateIpv4AddressGroupByIdOrName` | Update an IPv4 group |

### Network address groups IPv6

Manage IPv6 address groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/address-groups/ipv6` | `getAllIpv6AddressGroups` | Get all IPv6 groups |
| POST | `/network/address-groups/ipv6` | `createIpv6AddressGroup` | Create an IPv6 group |
| POST | `/network/address-groups/ipv6/delete` | `bulkDeleteIpv6AddressGroups` | Bulk delete IPv6 groups |
| DELETE | `/network/address-groups/ipv6/{idOrName}` | `deleteIpv6AddressGroupByIdOrName` | Delete an IPv6 group |
| GET | `/network/address-groups/ipv6/{idOrName}` | `getIpv6AddressGroupByIdOrName` | Get an IPv6 address group |
| PATCH | `/network/address-groups/ipv6/{idOrName}` | `updateIpv6AddressGroupByIdOrName` | Update an IPv6 group |

### Network address groups country

Manage country groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/address-groups/country` | `getAllCountryGroups` | Get all country groups |
| POST | `/network/address-groups/country` | `createCountryGroup` | Create a country group |
| POST | `/network/address-groups/country/delete` | `bulkDeleteCountryGroups` | Bulk delete groups |
| DELETE | `/network/address-groups/country/{idOrName}` | `deleteCountryGroupByIdOrName` | Delete a country group |
| GET | `/network/address-groups/country/{idOrName}` | `getCountryGroupByIdOrName` | Get country group |
| PATCH | `/network/address-groups/country/{idOrName}` | `updateCountryGroupByIdOrName` | Update a country group |

### Network addresses FQDN

Manage FQDNs.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/addresses/fqdn` | `getAllFqdns` | Get all FQDNs |
| POST | `/network/addresses/fqdn` | `createFqdn` | Create a FQDN |
| POST | `/network/addresses/fqdn/delete` | `bulkDeleteFqdns` | Bulk delete FQDNs |
| DELETE | `/network/addresses/fqdn/{idOrName}` | `deleteFqdnByIdOrName` | Delete a FQDN |
| GET | `/network/addresses/fqdn/{idOrName}` | `getFqdnByIdOrName` | Get a FQDN |
| PATCH | `/network/addresses/fqdn/{idOrName}` | `updateFqdnByIdOrName` | Update a FQDN |

### Network addresses IPv4

Manage IPv4 addresses.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/addresses/ipv4` | `getAllIpAddresses` | Get all IPv4 addresses |
| POST | `/network/addresses/ipv4` | `createIpAddress` | Create an IPv4 address |
| POST | `/network/addresses/ipv4/delete` | `bulkDeleteIpAddresses` | Bulk delete IPv4 |
| DELETE | `/network/addresses/ipv4/{idOrName}` | `deleteIpAddressByIdOrName` | Delete an IPv4 address |
| GET | `/network/addresses/ipv4/{idOrName}` | `getIpAddressByIdOrName` | Get an IPv4 address |
| PATCH | `/network/addresses/ipv4/{idOrName}` | `updateIpAddressByIdOrName` | Update an IPv4 address |

### Network addresses IPv6

Manage IPv6 addresses.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/addresses/ipv6` | `getAllIpv6Addresses` | Get all IPv6 addresses |
| POST | `/network/addresses/ipv6` | `createIpv6Address` | Create an IPv6 address |
| POST | `/network/addresses/ipv6/delete` | `bulkDeleteIpv6Addresses` | Bulk delete IPv6 |
| DELETE | `/network/addresses/ipv6/{idOrName}` | `deleteIpv6AddressByIdOrName` | Delete an IPv6 address |
| GET | `/network/addresses/ipv6/{idOrName}` | `getIpv6AddressByIdOrName` | Get an IPv6 address |
| PATCH | `/network/addresses/ipv6/{idOrName}` | `updateIpv6AddressByIdOrName` | Update an IPv6 address |

### Network addresses MAC

Manage MAC addresses.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/addresses/mac` | `getAllMacAddresses` | Get all MAC addresses |
| POST | `/network/addresses/mac` | `createMacAddress` | Create a MAC address |
| POST | `/network/addresses/mac/delete` | `bulkDeleteMacAddresses` | Bulk delete MAC addresses |
| DELETE | `/network/addresses/mac/{idOrName}` | `deleteMacAddressByIdOrName` | Delete a MAC address |
| GET | `/network/addresses/mac/{idOrName}` | `getMacAddressByIdOrName` | Get a MAC address |
| PATCH | `/network/addresses/mac/{idOrName}` | `updateMacAddressByIdOrName` | Update a MAC address |

### Network cellular WAN

Operations related to cellular WAN (WWAN) settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| POST | `/network/cellular-wan/connect-modem` | `connectCellularWan` | Connect cellular WAN |
| POST | `/network/cellular-wan/disconnect-modem` | `disconnectCellularWan` | Disconnect cellular WAN |
| GET | `/network/cellular-wan/modem-settings` | `getCellularWanModemSettings` | Get cellular modem settings |
| PATCH | `/network/cellular-wan/modem-settings` | `patchCellularWanModemSettings` | Update cellular modem settings |
| GET | `/network/cellular-wan/modem-status` | `getCellularWanStatus` | Get cellular modem status |
| POST | `/network/cellular-wan/recommended-modem-settings` | `queryRecommendedCellularWanSettings` | Query recommended settings |
| POST | `/network/cellular-wan/reset-modem` | `resetCellularWan` | Reset cellular WAN |
| GET | `/network/cellular-wan/settings` | `getCellularWanSettings` | Get cellular WAN settings |
| PATCH | `/network/cellular-wan/settings` | `patchCellularWanSettings` | Update cellular WAN settings |

### Network interfaces

Operations related to network interfaces.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/interfaces/network-interfaces` | `listNetworkInterfaces` | Get all interfaces |
| POST | `/network/interfaces/network-interfaces` | `createNetworkInterface` | Create an interface |
| DELETE | `/network/interfaces/network-interfaces/{idOrName}` | `deleteNetworkInterface` | Delete an interface |
| GET | `/network/interfaces/network-interfaces/{idOrName}` | `getNetworkInterface` | Get an interface |
| PATCH | `/network/interfaces/network-interfaces/{idOrName}` | `updateNetworkInterface` | Update an interface |

### Network mDNS configuration

Configure mDNS reflector settings for multicast DNS packet reflection between network interfaces.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/mdns-reflector` | `getMdnsConfiguration` | Get mDNS configuration |
| PATCH | `/network/mdns-reflector` | `updateMdnsConfiguration` | Update mDNS configuration |

### Network neighbor configuration

Operations related to neighbor settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/neighbors/settings` | `getNeighborConfiguration` | Get neighbor settings |
| PATCH | `/network/neighbors/settings` | `updateNeighborConfiguration` | Update neighbor settings |

### Network neighbors

Operations related to neighbor management.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/neighbors/static/ipv4` | `getAllStaticNeighborIpv4s` | Get all neighbors |
| POST | `/network/neighbors/static/ipv4` | `createStaticNeighborIpv4` | Create a static neighbor |
| POST | `/network/neighbors/static/ipv4/delete` | `bulkDeleteStaticNeighborIpv4s` | Bulk delete neighbors |
| DELETE | `/network/neighbors/static/ipv4/{idOrName}` | `deleteStaticNeighborIpv4` | Delete a static neighbor |
| GET | `/network/neighbors/static/ipv4/{idOrName}` | `getStaticNeighborIpv4` | Get a static neighbor |
| PATCH | `/network/neighbors/static/ipv4/{idOrName}` | `updateStaticNeighborIpv4` | Update a static neighbor |
| GET | `/network/neighbors/static/ipv6` | `getAllStaticNeighborIpv6s` | Get all neighbors |
| POST | `/network/neighbors/static/ipv6` | `createStaticNeighborIpv6` | Create a static neighbor |
| POST | `/network/neighbors/static/ipv6/delete` | `bulkDeleteStaticNeighborIpv6s` | Bulk delete neighbors |
| DELETE | `/network/neighbors/static/ipv6/{idOrName}` | `deleteStaticNeighborIpv6` | Delete a static neighbor |
| GET | `/network/neighbors/static/ipv6/{idOrName}` | `getStaticNeighborIpv6` | Get a static neighbor |
| PATCH | `/network/neighbors/static/ipv6/{idOrName}` | `updateStaticNeighborIpv6` | Update a static neighbor |

### Network router advertisements

Operations related to router advertisements.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/router-advertisements` | `getRouterAdvertisements` | Get all router ads |
| POST | `/network/router-advertisements` | `createRouterAdvertisement` | Create a router ad |
| POST | `/network/router-advertisements/delete` | `bulkDeleteRouterAdvertisements` | Bulk delete router ads |
| DELETE | `/network/router-advertisements/{idOrName}` | `deleteRouterAdvertisement` | Delete a router ad |
| GET | `/network/router-advertisements/{idOrName}` | `getRouterAdvertisement` | Get a router ad |
| PATCH | `/network/router-advertisements/{idOrName}` | `updateRouterAdvertisement` | Update a router ad |

### Network service groups

Manage service groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/service-groups` | `getAllServiceGroups` | Get all service groups |
| POST | `/network/service-groups` | `createServiceGroup` | Create a Service group |
| POST | `/network/service-groups/delete` | `bulkDeleteServiceGroups` | Bulk delete groups |
| DELETE | `/network/service-groups/{idOrName}` | `deleteServiceGroupByIdOrName` | Delete a service group |
| GET | `/network/service-groups/{idOrName}` | `getServiceGroupByIdOrName` | Get a service group |
| PATCH | `/network/service-groups/{idOrName}` | `updateServiceGroupByIdOrName` | Update a service group |

### Network services

Manage services.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/services` | `getAllServices` | Get all Services |
| POST | `/network/services` | `createService` | Create a Service |
| POST | `/network/services/delete` | `bulkDeleteServices` | Bulk delete Services |
| DELETE | `/network/services/{idOrName}` | `deleteServiceByIdOrName` | Delete a Service |
| GET | `/network/services/{idOrName}` | `getServiceByIdOrName` | Get a Service |
| PATCH | `/network/services/{idOrName}` | `updateServiceByIdOrName` | Update a Service |

### Network zones

Operations related to zones.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/network/zones` | `getAllZones` | Get all zones |
| POST | `/network/zones` | `createZone` | Create a zone |
| POST | `/network/zones/delete` | `bulkDeleteZones` | Bulk delete zones |
| DELETE | `/network/zones/{idOrName}` | `deleteZone` | Delete a zone |
| GET | `/network/zones/{idOrName}` | `getZone` | Get a zone |
| PATCH | `/network/zones/{idOrName}` | `updateZone` | Update a zone |

### Notification list

Manage alert notification settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/notification/notifications` | `getAlertNotificationSettings` | Get notification prefs |
| PATCH | `/notification/notifications` | `updateAlertNotificationSettings` | Update notification prefs |

### Routing gateways

Manage gateways, including WAN gateways and custom gateways.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/routing/gateways/custom/ipv4` | `getCustomGatewaysIpv4` | Get all IPv4 gateways |
| POST | `/routing/gateways/custom/ipv4` | `createCustomGatewayIpv4` | Create an IPv4 gateway |
| POST | `/routing/gateways/custom/ipv4/delete` | `bulkDeleteCustomGatewaysIpv4` | Bulk delete IPv4 gateways |
| DELETE | `/routing/gateways/custom/ipv4/{idOrName}` | `deleteCustomGatewayIpv4` | Delete an IPv4 gateway |
| GET | `/routing/gateways/custom/ipv4/{idOrName}` | `getCustomGatewayIpv4ByIdOrName` | Get an IPv4 gateway |
| PATCH | `/routing/gateways/custom/ipv4/{idOrName}` | `patchCustomGatewayIpv4` | Update an IPv4 Gateway |
| GET | `/routing/gateways/custom/ipv6` | `getCustomGatewaysIpv6` | Get all IPv6 gateways |
| POST | `/routing/gateways/custom/ipv6` | `createCustomGatewayIpv6` | Create an IPv6 gateway |
| POST | `/routing/gateways/custom/ipv6/delete` | `bulkDeleteCustomGatewaysIpv6` | Bulk delete IPv6 gateways |
| DELETE | `/routing/gateways/custom/ipv6/{idOrName}` | `deleteCustomGatewayIpv6` | Delete an IPv6 gateway |
| GET | `/routing/gateways/custom/ipv6/{idOrName}` | `getCustomGatewayIpv6ByIdOrName` | Get an IPv6 gateway |
| PATCH | `/routing/gateways/custom/ipv6/{idOrName}` | `patchCustomGatewayIpv6` | Update an IPv6 gateway |
| GET | `/routing/gateways/ipv4` | `getGatewaysIpv4` | Get all IPv4 gateways |
| GET | `/routing/gateways/ipv6` | `getGatewaysIpv6` | Get all IPv6 gateways |
| GET | `/routing/gateways/wan/ipv4` | `getWanGatewaysIpv4` | Get all IPv4 gateways |
| GET | `/routing/gateways/wan/ipv4/{idOrName}` | `getWanGatewayIpv4ByIdOrName` | Get an IPv4 gateway |
| PATCH | `/routing/gateways/wan/ipv4/{idOrName}` | `patchWanGatewayIpv4` | Update an IPv4 gateway |
| GET | `/routing/gateways/wan/ipv6` | `getWanGatewaysIpv6` | Get all IPv6 gateways |
| GET | `/routing/gateways/wan/ipv6/{idOrName}` | `getWanGatewayIpv6ByIdOrName` | Get an IPv6 gateway |
| PATCH | `/routing/gateways/wan/ipv6/{idOrName}` | `patchWanGatewayIpv6` | Update an IPv6 gateway |

### Routing multicast routes

Manage IPv4 multicast routes.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/routing/static-multicast-routes/ipv4` | `getMulticastRoutesIPv4` | Retrieve Multicast Routes |
| POST | `/routing/static-multicast-routes/ipv4` | `createMulticastRouteIPv4` | Create Multicast Route |
| POST | `/routing/static-multicast-routes/ipv4/delete` | `bulkDeleteMulticastRoutesIPv4` | Delete Multicast Routes |
| DELETE | `/routing/static-multicast-routes/ipv4/{idOrName}` | `deleteMulticastRouteIPv4` | Delete Multicast Route |
| GET | `/routing/static-multicast-routes/ipv4/{idOrName}` | `getMulticastRouteIPv4` | Retrieve Multicast Route |
| PATCH | `/routing/static-multicast-routes/ipv4/{idOrName}` | `updateMulticastRouteIPv4` | Update Multicast Route |

### Routing multicast settings

Multicast forwarding settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/routing/static-multicast-settings` | `getMulticastForwardingSettings` | Get multicast settings |
| PATCH | `/routing/static-multicast-settings` | `updateMulticastForwardingSettings` | Update multicast settings |

### Routing unicast routes

Manage unicast routes.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/routing/static-unicast-routes/ipv4` | `getUnicastRoutesIPv4` | List IPv4 unicast routes |
| POST | `/routing/static-unicast-routes/ipv4` | `createUnicastRouteIPv4` | Create IPv4 Unicast Route |
| POST | `/routing/static-unicast-routes/ipv4/delete` | `bulkDeleteUnicastRoutesIPv4` | Bulk delete IPv4 routes |
| DELETE | `/routing/static-unicast-routes/ipv4/{idOrName}` | `deleteUnicastRouteIPv4` | Delete IPv4 Unicast Route |
| GET | `/routing/static-unicast-routes/ipv4/{idOrName}` | `getUnicastRouteIPv4` | Get IPv4 unicast route |
| PATCH | `/routing/static-unicast-routes/ipv4/{idOrName}` | `updateUnicastRouteIPv4` | Update IPv4 Unicast Route |
| GET | `/routing/static-unicast-routes/ipv6` | `getUnicastRoutesIPv6` | List IPv6 unicast routes |
| POST | `/routing/static-unicast-routes/ipv6` | `createUnicastRouteIPv6` | Create IPv6 Unicast Route |
| POST | `/routing/static-unicast-routes/ipv6/delete` | `bulkDeleteUnicastRoutesIPv6` | Bulk delete IPv6 routes |
| DELETE | `/routing/static-unicast-routes/ipv6/{idOrName}` | `deleteUnicastRouteIPv6` | Delete IPv6 Unicast Route |
| GET | `/routing/static-unicast-routes/ipv6/{idOrName}` | `getUnicastRouteIPv6` | Get IPv6 unicast route |
| PATCH | `/routing/static-unicast-routes/ipv6/{idOrName}` | `updateUnicastRouteIPv6` | Update IPv6 Unicast Route |

### SD-WAN routes

Manage SD-WAN routes.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/sd-wan/routes/ipv4` | `listSdwanRoutesIpv4` | List IPv4 SD-WAN routes |
| POST | `/sd-wan/routes/ipv4` | `createSdwanRouteIpv4` | Create IPv4 SD-WAN route |
| POST | `/sd-wan/routes/ipv4/delete` | `bulkDeleteSdwanRoutesIpv4` | Bulk delete IPv4 SD-WAN routes |
| POST | `/sd-wan/routes/ipv4/move` | `moveSdwanRouteIpv4` | Move IPv4 SD-WAN route |
| DELETE | `/sd-wan/routes/ipv4/{idOrName}` | `deleteSdwanRouteIpv4` | Delete IPv4 SD-WAN route |
| GET | `/sd-wan/routes/ipv4/{idOrName}` | `getSdwanRouteIpv4` | Get IPv4 SD-WAN Route |
| PATCH | `/sd-wan/routes/ipv4/{idOrName}` | `updateSdwanRouteIpv4` | Update IPv4 SD-WAN Route |
| GET | `/sd-wan/routes/ipv6` | `listSdwanRoutesIpv6` | List IPv6 SD-WAN routes |
| POST | `/sd-wan/routes/ipv6` | `createSdwanRouteIpv6` | Create IPv6 SD-WAN route |
| POST | `/sd-wan/routes/ipv6/delete` | `bulkDeleteSdwanRoutesIpv6` | Bulk delete IPv6 SD-WAN routes |
| POST | `/sd-wan/routes/ipv6/move` | `moveSdwanRouteIpv6` | Move IPv6 SD-WAN route |
| DELETE | `/sd-wan/routes/ipv6/{idOrName}` | `deleteSdwanRouteIpv6` | Delete IPv6 SD-WAN route |
| GET | `/sd-wan/routes/ipv6/{idOrName}` | `getSdwanRouteIpv6` | Get IPv6 SD-WAN route |
| PATCH | `/sd-wan/routes/ipv6/{idOrName}` | `updateSdwanRouteIpv6` | Update IPv6 SD-WAN route |

### SSL VPN bookmark groups

Operations for clientless SSL VPN bookmark groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ssl-vpn/clientless/bookmark-groups` | `listBookmarkGroups` | List bookmark groups |
| POST | `/ssl-vpn/clientless/bookmark-groups` | `createBookmarkGroup` | Create a bookmark group |
| POST | `/ssl-vpn/clientless/bookmark-groups/delete` | `bulkDeleteBookmarkGroups` | Bulk delete groups |
| DELETE | `/ssl-vpn/clientless/bookmark-groups/{idOrName}` | `deleteBookmarkGroup` | Delete a bookmark group |
| GET | `/ssl-vpn/clientless/bookmark-groups/{idOrName}` | `getBookmarkGroup` | Retrieve a bookmark group |
| PATCH | `/ssl-vpn/clientless/bookmark-groups/{idOrName}` | `patchBookmarkGroup` | Update a bookmark group |

### SSL VPN bookmarks

Operations for clientless SSL VPN bookmarks.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ssl-vpn/clientless/bookmarks` | `getBookmarks` | Get all bookmarks |
| POST | `/ssl-vpn/clientless/bookmarks` | `createBookmark` | Create a bookmark |
| POST | `/ssl-vpn/clientless/bookmarks/delete` | `bulkDeleteBookmarks` | Bulk delete bookmarks |
| DELETE | `/ssl-vpn/clientless/bookmarks/{idOrName}` | `deleteBookmark` | Delete a bookmark |
| GET | `/ssl-vpn/clientless/bookmarks/{idOrName}` | `getBookmark` | Get a bookmark |
| PATCH | `/ssl-vpn/clientless/bookmarks/{idOrName}` | `updateBookmark` | Update a bookmark |

### SSL VPN clientless policies

SSL VPN Web Access (clientless) policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ssl-vpn/clientless/policies` | `listClientlessPolicies` | List clientless policies |
| POST | `/ssl-vpn/clientless/policies` | `createClientlessPolicy` | Create clientless policy |
| POST | `/ssl-vpn/clientless/policies/delete` | `bulkDeleteClientlessPolicies` | Bulk delete policies |
| DELETE | `/ssl-vpn/clientless/policies/{idOrName}` | `deleteClientlessPolicy` | Delete clientless policy |
| GET | `/ssl-vpn/clientless/policies/{idOrName}` | `getClientlessPolicy` | Get clientless policy |
| PATCH | `/ssl-vpn/clientless/policies/{idOrName}` | `updateClientlessPolicy` | Update clientless policy |

### SSL VPN global settings

SSL VPN global settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ssl-vpn/global-settings` | `getSslvpnGlobalSettings` | Get SSL VPN settings |
| PATCH | `/ssl-vpn/global-settings` | `updateSslvpnGlobalSettings` | Update SSL VPN settings |

### SSL VPN remote access policies

Remote access SSL VPN policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/ssl-vpn/remote-access/policies` | `getRemoteAccessPolicies` | Get all policies |
| POST | `/ssl-vpn/remote-access/policies` | `createRemoteAccessPolicy` | Create a policy |
| POST | `/ssl-vpn/remote-access/policies/delete` | `deleteRemoteAccessPolicies` | Bulk delete policies |
| DELETE | `/ssl-vpn/remote-access/policies/{idOrName}` | `deleteRemoteAccessPolicy` | Delete a policy |
| GET | `/ssl-vpn/remote-access/policies/{idOrName}` | `getRemoteAccessPolicy` | Get a policy |
| PATCH | `/ssl-vpn/remote-access/policies/{idOrName}` | `updateRemoteAccessPolicy` | Update a policy |

### SSL/TLS inspection decryption profiles

Operations related to SSL/TLS inspection decryption profiles.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/tls-inspection/decryption-profiles` | `getDecryptionProfiles` | List decryption profiles |
| POST | `/tls-inspection/decryption-profiles` | `createDecryptionProfile` | Create decryption profile |
| POST | `/tls-inspection/decryption-profiles/delete` | `bulkDeleteDecryptionProfiles` | Delete profile list |
| DELETE | `/tls-inspection/decryption-profiles/{idOrName}` | `deleteDecryptionProfile` | Delete decryption profile |
| GET | `/tls-inspection/decryption-profiles/{idOrName}` | `getDecryptionProfile` | Get decryption profile |
| PATCH | `/tls-inspection/decryption-profiles/{idOrName}` | `updateDecryptionProfile` | Update decryption profile |

### SSL/TLS inspection rules

Operations related to SSL/TLS inspection rules.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/tls-inspection/rules/ipv4` | `listSslTlsInspectionRules` | List SSL TLS rules |
| POST | `/tls-inspection/rules/ipv4` | `createSslTlsInspectionRule` | Create an SSL TLS rule |
| POST | `/tls-inspection/rules/ipv4/delete` | `bulkDeleteSslTlsInspectionRules` | Delete SSL TLS rule list |
| POST | `/tls-inspection/rules/ipv4/move` | `moveSslTlsInspectionRule` | Move SSL TLS rule |
| DELETE | `/tls-inspection/rules/ipv4/{idOrName}` | `deleteSslTlsInspectionRule` | Delete an SSL TLS rule |
| GET | `/tls-inspection/rules/ipv4/{idOrName}` | `getSslTlsInspectionRule` | Get an SSL TLS rule |
| PATCH | `/tls-inspection/rules/ipv4/{idOrName}` | `updateSslTlsInspectionRule` | Update an SSL TLS rule |

### SSL/TLS inspection settings

Operations related to SSL/TLS inspection settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/tls-inspection/settings` | `getSslTlsInspectionSettings` | Get TLS settings |
| PATCH | `/tls-inspection/settings` | `updateSslTlsInspectionSettings` | Update TLS settings |

### Sophos Central

Operations related to Sophos Central registration and services settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| POST | `/sophos-central/deregister` | `deregisterFirewall` | Deregister firewall |
| POST | `/sophos-central/register` | `registerFirewall` | Register firewall |
| GET | `/sophos-central/settings` | `getSophosCentralSettings` | Get settings |
| PATCH | `/sophos-central/settings` | `updateSophosCentralSettings` | Update settings |
| GET | `/sophos-central/status` | `getRegistrationStatus` | Get registration status |

### Spoof protection general settings

Manage spoof protection general settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/spoof-protection/settings` | `getSpoofSettings` | Returns general settings |
| PATCH | `/spoof-protection/settings` | `updateSpoofSettings` | Updates general settings |

### Spoof protection trusted MACs

Add, update, view or delete trusted MACs.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/spoof-protection/trusted-macs` | `getAllTrustedMacs` | Returns trusted macs |
| POST | `/spoof-protection/trusted-macs` | `createTrustedMac` | Creates trusted mac |
| POST | `/spoof-protection/trusted-macs/delete` | `bulkDeleteTrustedMacs` | Bulk delete trusted-macs |
| POST | `/spoof-protection/trusted-macs/import` | `importTrustedMacs` | Upload a file |
| DELETE | `/spoof-protection/trusted-macs/{idOrName}` | `deleteTrustedMacByIdOrName` | Remove trusted mac |
| GET | `/spoof-protection/trusted-macs/{idOrName}` | `getTrustedMacByIdOrName` | Retrieve trusted mac |
| PATCH | `/spoof-protection/trusted-macs/{idOrName}` | `updateTrustedMacByIdOrName` | Update trusted mac |

### Support access

Manage temporary remote support access settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/administration/support-access` | `getSupportAccessSetting` | Get a support access |
| PATCH | `/administration/support-access` | `updateSupportAccessSetting` | Update a support access |

### System automatic pattern updates

Operations related to automatic pattern updates.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/system/pattern-updates/settings` | `getPatternSettings` | Get auto-update settings |
| PATCH | `/system/pattern-updates/settings` | `updatePatternSettings` | Modify auto-updates |

### System backup settings

Operations related to backup settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/system/backup/settings` | `getBackupScheduleSettings` | Get a backup schedule |
| PATCH | `/system/backup/settings` | `updateBackupScheduleSettings` | Update a backup schedule |

### System hotfix settings

Manage hotfix settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/system/hotfix/settings` | `getHotfix` | Retrieve hotfix settings |

### System security updates

Get applied hotfix security updates.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/system/security-updates` | `listSecurityUpdates` | List security updates |

### Traffic shaping policies

Operations related to traffic shaping bandwidth policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/traffic-shaping/policies` | `listTrafficShapingPolicies` | Get all policies |
| POST | `/traffic-shaping/policies` | `createTrafficShapingPolicy` | Create a policy |
| POST | `/traffic-shaping/policies/delete` | `bulkDeleteTrafficShapingPolicies` | Bulk delete policies |
| DELETE | `/traffic-shaping/policies/{idOrName}` | `deleteTrafficShapingPolicy` | Delete a policy |
| GET | `/traffic-shaping/policies/{idOrName}` | `getTrafficShapingPolicy` | Get a policy |
| PATCH | `/traffic-shaping/policies/{idOrName}` | `updateTrafficShapingPolicy` | Update a policy |

### Traffic shaping settings

Manage global traffic shaping settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/traffic-shaping/settings` | `getTrafficShapingSettings` | Get settings |
| PATCH | `/traffic-shaping/settings` | `updateTrafficShapingSettings` | Update settings |

### WAF authentication policies

Operations related to WAF authentication policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/waf/authentication/policies` | `listAuthenticationPolicies` | List policies |
| POST | `/waf/authentication/policies` | `createAuthenticationPolicy` | Create policy |
| POST | `/waf/authentication/policies/delete` | `bulkDeleteAuthenticationPolicies` | Delete policies |
| DELETE | `/waf/authentication/policies/{idOrName}` | `deleteAuthenticationPolicy` | Delete policy |
| GET | `/waf/authentication/policies/{idOrName}` | `getAuthenticationPolicy` | Get policy |
| PATCH | `/waf/authentication/policies/{idOrName}` | `updateAuthenticationPolicy` | Update policy |

### WAF authentication templates

Operations related to WAF authentication templates.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/waf/authentication/templates` | `listAuthenticationTemplates` | Get all templates |
| POST | `/waf/authentication/templates` | `createAuthenticationTemplate` | Create a template |
| POST | `/waf/authentication/templates/delete` | `bulkDeleteAuthenticationTemplates` | Bulk delete templates |
| DELETE | `/waf/authentication/templates/{idOrName}` | `deleteAuthenticationTemplate` | Delete a template |
| GET | `/waf/authentication/templates/{idOrName}` | `getAuthenticationTemplate` | Get a template |
| PATCH | `/waf/authentication/templates/{idOrName}` | `updateAuthenticationTemplate` | Update a template |

### WAF protection policies

Operations related to WAF protection policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/waf/protection/policies` | `listProtectionPolicies` | List protection policies |
| POST | `/waf/protection/policies` | `createProtectionPolicy` | Create protection policy |
| POST | `/waf/protection/policies/delete` | `bulkDeleteProtectionPolicies` | Bulk delete policies |
| DELETE | `/waf/protection/policies/{idOrName}` | `deleteProtectionPolicy` | Delete protection policy |
| GET | `/waf/protection/policies/{idOrName}` | `getProtectionPolicy` | Get protection policy |
| PATCH | `/waf/protection/policies/{idOrName}` | `updateProtectionPolicy` | Update protection policy |

### WAF web servers

Operations related to WAF web servers.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/waf/servers` | `listWebServers` | List web servers |
| POST | `/waf/servers` | `createWebServer` | Create web server |
| POST | `/waf/servers/delete` | `bulkDeleteWebServers` | Delete web servers |
| DELETE | `/waf/servers/{idOrName}` | `deleteWebServer` | Delete web server |
| GET | `/waf/servers/{idOrName}` | `getWebServer` | Get web server |
| PATCH | `/waf/servers/{idOrName}` | `updateWebServer` | Update web server |

### Web filter URL groups

Operations related to web filter URL groups.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/url-groups` | `listWebFilterUrlGroups` | List URL groups |
| POST | `/web/url-groups` | `createWebFilterUrlGroup` | Create a URL group |
| POST | `/web/url-groups/delete` | `bulkDeleteWebFilterUrlGroups` | Delete URL group list |
| DELETE | `/web/url-groups/{idOrName}` | `deleteWebFilterUrlGroup` | Delete a URL group |
| GET | `/web/url-groups/{idOrName}` | `getWebFilterUrlGroup` | Get a URL group |
| PATCH | `/web/url-groups/{idOrName}` | `updateWebFilterUrlGroup` | Update a URL group |

### Web filter categories

Operations related to web filter categories.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/categories` | `listWebFilterCategories` | List web categories |
| POST | `/web/categories` | `createWebFilterCategory` | Create a web category |
| POST | `/web/categories/delete` | `bulkDeleteWebFilterCategories` | Delete web category list |
| DELETE | `/web/categories/{idOrName}` | `deleteWebFilterCategory` | Delete a web category |
| GET | `/web/categories/{idOrName}` | `getWebFilterCategory` | Get a web category |
| PATCH | `/web/categories/{idOrName}` | `updateWebFilterCategory` | Update a web category |

### Web filter content condition lists

Operations related to web filter content filters (content condition lists).

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/content-filters` | `listContentFilters` | List content filters |
| POST | `/web/content-filters` | `createContentFilter` | Create a content filter |
| POST | `/web/content-filters/delete` | `bulkDeleteContentFilters` | Delete filter list |
| DELETE | `/web/content-filters/{idOrName}` | `deleteContentFilter` | Delete a content filter |
| GET | `/web/content-filters/{idOrName}` | `getContentFilter` | Get a content filter |
| PATCH | `/web/content-filters/{idOrName}` | `updateContentFilter` | Update a content filter |

### Web filter exceptions

Operations related to web filter exceptions.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/exceptions` | `listWebFilterExceptions` | List web exceptions |
| POST | `/web/exceptions` | `createWebFilterException` | Create a web exception |
| POST | `/web/exceptions/delete` | `bulkDeleteWebFilterExceptions` | Delete web exception list |
| DELETE | `/web/exceptions/{idOrName}` | `deleteWebFilterException` | Delete a web exception |
| GET | `/web/exceptions/{idOrName}` | `getWebFilterException` | Get a web exception |
| PATCH | `/web/exceptions/{idOrName}` | `updateWebFilterException` | Update a web exception |

### Web filter policies

Operations related to web filter policies.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/policies` | `listWebFilterPolicies` | List web policies |
| POST | `/web/policies` | `createWebFilterPolicy` | Create a web policy |
| POST | `/web/policies/delete` | `bulkDeleteWebFilterPolicies` | Delete web policy list |
| DELETE | `/web/policies/{idOrName}` | `deleteWebFilterPolicy` | Delete a web policy |
| GET | `/web/policies/{idOrName}` | `getWebFilterPolicy` | Get a web policy |
| PATCH | `/web/policies/{idOrName}` | `updateWebFilterPolicy` | Update a web policy |

### Web filter protection settings

Operations related to web filter protection settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/scan-settings` | `getWebScanSettings` | Get scan settings |
| PATCH | `/web/scan-settings` | `updateWebScanSettings` | Update scan settings |

### Web filter user activities

Operations related to web filter user activities.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/user-activities` | `listUserActivities` | List user activities |
| POST | `/web/user-activities` | `createUserActivity` | Create a user activity |
| POST | `/web/user-activities/delete` | `bulkDeleteUserActivities` | Delete user activity list |
| DELETE | `/web/user-activities/{idOrName}` | `deleteUserActivity` | Delete a user activity |
| GET | `/web/user-activities/{idOrName}` | `getUserActivity` | Get a user activity |
| PATCH | `/web/user-activities/{idOrName}` | `updateUserActivity` | Update a user activity |

### Web filter user notification settings

Operations related to web filter user notification settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/web/user-notifications` | `getWebFilterNotificationSettings` | Get notification settings |
| PATCH | `/web/user-notifications` | `updateWebFilterNotificationSettings` | Update notification |

### Wireless hotspot settings

Operations related to hotspot captive portal settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/wireless/hotspot/settings` | `getHotspotSettings` | Get hotspot settings |
| PATCH | `/wireless/hotspot/settings` | `updateHotspotSettings` | Update hotspot settings |

### Wireless hotspot vouchers

Operations related to hotspot vouchers.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/wireless/hotspot/vouchers` | `listVouchers` | Get all vouchers |
| POST | `/wireless/hotspot/vouchers` | `createVoucher` | Create a voucher |
| POST | `/wireless/hotspot/vouchers/delete` | `bulkDeleteVouchers` | Bulk delete vouchers |
| DELETE | `/wireless/hotspot/vouchers/{idOrName}` | `deleteVoucher` | Delete a voucher |
| GET | `/wireless/hotspot/vouchers/{idOrName}` | `getVoucher` | Get a voucher |
| PATCH | `/wireless/hotspot/vouchers/{idOrName}` | `updateVoucher` | Update a voucher |

### Wireless hotspots

Operations related to hotspots.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/wireless/hotspot/hotspots` | `listHotspots` | Get all hotspots |
| POST | `/wireless/hotspot/hotspots` | `createHotspot` | Create a hotspot |
| POST | `/wireless/hotspot/hotspots/delete` | `bulkDeleteHotspots` | Bulk delete hotspots |
| DELETE | `/wireless/hotspot/hotspots/{idOrName}` | `deleteHotspot` | Delete a hotspot |
| GET | `/wireless/hotspot/hotspots/{idOrName}` | `getHotspot` | Get a hotspot |
| PATCH | `/wireless/hotspot/hotspots/{idOrName}` | `updateHotspot` | Update a hotspot |

### Zero-day protection

Operations related to zero-day protection settings.

| Método | Ruta | operationId | Resumen |
|---|---|---|---|
| GET | `/zero-day-protection/settings` | `getZeroDayProtectionSettings` | Get zero-day settings |
| PATCH | `/zero-day-protection/settings` | `updateZeroDayProtectionSettings` | Update zero-day settings |
