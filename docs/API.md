# Vylaris Unified API v1 (log_in-Seite)

Maschinenlesbar: [openapi.yaml](openapi.yaml) (OpenAPI 3.1). Testvektoren: [test-vectors.json](test-vectors.json). Alle drei Projekte (Dash, log_in, Reseller) verwenden diesen Vertrag; Reseller spricht **nie** mit log_in.

## 1. Pfadraum und Discovery

Einziger Pfadraum fuer Maschinenkommunikation: **`/api/vylaris/v1`** (zentral in `config('vylaris.api_prefix')`). Die frueheren Pfade `/api/dash/v1/*` und `/log-in/*` existieren nicht mehr (404, getestet in `MachineContractTest`).

| Zweck | Pfad | Signiert |
|---|---|---|
| Vylaris-Discovery log_in | `GET /api/vylaris/v1/discovery` (Alias: `GET /.well-known/vylaris-login`) | nein (dokumentierte Ausnahme) |
| OIDC-Metadaten | `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json` | nein (Standard) |
| Dash-Discovery (von Dash bereitzustellen) | `GET <dash>/.well-known/vylaris-dash` | nein |

Discovery-Antwort log_in: `{"data":{"service":"log_in","api_version":"v1","version":"1.1.0","installation_id":"...","name":"Vylaris log_in","public_key":"<Ed25519 b64>","issuer":"https://...","api_base":"https://.../api/vylaris/v1","openid_configuration":"https://.../.well-known/openid-configuration"}}`. Der Schluessel ist erst nach Fingerprint-Bestaetigung vertrauenswuerdig.

## 2. Authentifizierung (jeder Maschinenrequest)

1. **`Authorization: Bearer <Service-Token>`** - Token-Kategorie *Service-API-Token* (Dash <-> log_in). Format `vlst_<43 Zeichen base64url>` (256 Bit). Gespeichert wird nur der SHA-256-Hash. Bindung an Installation, Scopes, Ablauf (Standard 90 Tage), Status. Weder ein OIDC-Access-Token noch ein Tool-API-Token wird akzeptiert (`invalid_token`); ein Service-Token impliziert keine Benutzerrechte.
2. **Ed25519-Signatur** ueber den kanonischen Request.

| Header | Inhalt |
|---|---|
| `Authorization` | `Bearer <token>` (nie in URL/Query) |
| `X-Vylaris-Key-Id` | Installations-ID des Senders (muss aktiver, registrierter Installation und dem Token entsprechen) |
| `X-Vylaris-Timestamp` | Unix-Sekunden, Abweichung <= 60 s |
| `X-Vylaris-Nonce` | 16-64 Zeichen `[A-Za-z0-9_-]`, pro Installation einmalig, mind. 180 s gespeichert |
| `X-Vylaris-Signature` | Base64 (Standardalphabet) der Ed25519-Detached-Signatur |
| `Idempotency-Key` | optional bei schreibenden Operationen, 8-128 Zeichen `[A-Za-z0-9_.:-]` |

```
VYLARIS-V1\n<METHOD>\n<PATH_AND_QUERY>\n<TIMESTAMP>\n<NONCE>\n<SHA256_HEX(raw body)>
```
(kein abschliessender Zeilenumbruch; Pfad inkl. Query exakt wie uebertragen; Hash des leeren Bodys = SHA-256 der leeren Bytefolge). Ein gueltiges Token **ohne** gueltige Signatur wird abgelehnt (und umgekehrt). Pruefreihenfolge: Bearer vorhanden -> Key-Id -> Token (Hash, Installation, Status, Ablauf) -> Signaturformat -> Zeitfenster -> Signatur -> Nonce (Replay) -> Scope.

**Antworten** (ausser Discovery) sind signiert: Header `X-Vylaris-Key-Id`, `X-Vylaris-Timestamp`, `X-Vylaris-Signature` ueber

```
VYLARIS-V1-RESP\n<STATUS>\n<REQUEST_NONCE>\n<RESPONSE_TIMESTAMP>\n<SHA256_HEX(raw response body)>
```
Auch Fehlerantworten nach erfolgreicher Authentifizierung (z. B. 403 `forbidden`) sind signiert. Antworten auf Requests mit ungueltiger Authentifizierung (401) sind es nicht - die Gegenstelle kann sie ohnehin nicht dem Request zuordnen.

## 3. Antwort- und Fehlervertrag

Erfolg: `{"data": {...}}`; Listen: `{"data": [...], "meta": {...}}`. Fehler: `{"error":{"code","message","details"?}}`. Keine Stacktraces, Schluessel- oder Token-Details.

| Code | HTTP | Bedeutung |
|---|---|---|
| `unauthorized` | 401 | Bearer fehlt oder Key-Id passt nicht |
| `invalid_token` | 401 | Token unbekannt/falsch/ersetzt (u. a. OIDC- oder Tool-Token) |
| `token_expired` | 401 | Token abgelaufen |
| `invalid_signature` | 401 | Signatur fehlt/ungueltig, Body manipuliert |
| `timestamp_out_of_range` | 401 | > 60 s Abweichung |
| `replay_detected` | 401 | Nonce bereits benutzt |
| `forbidden` | 403 | Scope fehlt, geschuetzter Client |
| `pairing_closed` | 409 | Kein Pairing-Fenster offen oder Zustand erlaubt Operation nicht |
| `pairing_expired` | 410 | Fenster/Pairing abgelaufen |
| `pairing_denied` | 403 | Pairing abgelehnt |
| `invalid_pairing_proof` | 422 / 409 | Nachweis falsch oder Challenge schon verbraucht |
| `installation_revoked` | 403 | Installation/Token widerrufen |
| `resource_not_found` | 404 | unbekannte Ressource oder Pfad |
| `duplicate_conflict` | 409 | Installation bereits gepairt, Pairing laeuft, ID-Konflikt |
| `idempotency_conflict` | 409 | Key mit anderem Request oder noch in Bearbeitung |
| `validation_failed` | 422 | Eingabe ungueltig (`details`) |
| `rate_limited` | 429 | Drosselung |
| `service_unavailable` | 503 | log_in noch nicht eingerichtet |
| `internal_error` | 500 | unerwarteter Fehler |

## 4. Endpunkte von log_in (Dash -> log_in)

Scopes des Service-Tokens: `service.health`, `pairings.manage`, `clients.read`, `clients.manage`, `keys.manage`, `users.revoke`, `service.rotate`.

| Methode & Pfad | Scope | Zweck | Erfolg |
|---|---|---|---|
| `GET /health` | service.health | Zustand | 200 |
| `GET /pairing-window` | pairings.manage | Fenster abfragen | 200 |
| `POST /pairing-window` | pairings.manage | Fenster oeffnen `{"duration_seconds":30-900}` (Standard 300) | 201 |
| `DELETE /pairing-window` | pairings.manage | Fenster schliessen | 200 |
| `POST /pairings` | pairings.manage | Pairing anlegen (nur bei offenem Fenster) | 201 / 200 bei Wiederholung |
| `GET /pairings/{id}` | pairings.manage | Zustand | 200 |
| `POST /pairings/{id}/approve` | pairings.manage | genehmigen, Body `{"approved_scopes":[...]}` | 200 |
| `POST /pairings/{id}/reject` | pairings.manage | ablehnen | 200 |
| `POST /pairings/{id}/cancel` | pairings.manage | abbrechen | 200 |
| `POST /pairings/{id}/confirm` | pairings.manage | Nachweis `{"proof":"<b64>"}`, aktiviert Client | 200 |
| `POST /pairings/{id}/credentials-ack` | pairings.manage | Empfang bestaetigt | 200 |
| `GET /clients` | clients.read | Clients (Kacheln), `meta.pending_pairings` | 200 |
| `GET /clients/{client_id}` | clients.read | ein Client | 200 |
| `PATCH /clients/{client_id}` | clients.manage | `redirect_uris`, `post_logout_uris`, `scopes`, `version` | 200 |
| `POST /clients/{client_id}/suspend` `/resume` `/disconnect` `/report-error` `/rotate-secret` | clients.manage | Lebenszyklus | 200 |
| `GET /keys` | keys.manage | OIDC-Signaturschluessel (`key_id`, ohne private Teile) | 200 |
| `POST /keys/rotate` | keys.manage | Rotation | 201 |
| `POST /keys/{key_id}/revoke` | keys.manage | Sofortwiderruf | 200 |
| `POST /users/{sub}/revoke` | users.revoke | Sitzungen + Tokens widerrufen | 200 `{sub, revoked_sessions}` |
| `POST /users/{sub}/refresh` | users.revoke | Identitaets-Cache invalidieren | 200 |
| `POST /service-tokens/rotate` | service.rotate | Service-Token rotieren (siehe 6) | 200 |

Rate-Limit 300/min. Idempotenz: bei gesetztem `Idempotency-Key` wird die Antwort 24 h gespeichert; Wiederholung mit gleichem Body liefert dieselbe Antwort (`Idempotent-Replayed: true`, neu signiert), anderer Body -> `idempotency_conflict`.

Der Dash-Client (`is_dash`) kann nicht gesperrt oder getrennt werden (`forbidden`, `details.reason = dash_client_protected`).

## 5. Endpunkte, die Dash bereitstellen muss (log_in -> Dash)

Basis `<dash>/api/vylaris/v1`; Bearer = `login_to_dash_token`, `X-Vylaris-Key-Id` = log_in-Installations-ID. Dash signiert seine Antworten (`X-Vylaris-Key-Id` = Dash-Installations-ID).

| Methode & Pfad | Quelle | Zweck |
|---|---|---|
| `GET /.well-known/vylaris-dash` | Masterspezifikation | Discovery (unsigniert), `{"data":{api_version:"v1", installation_id, name, public_key, box_public_key?}}` |
| `GET /health` | Masterspezifikation | `{"data":{"status":"ok"}}` |
| `GET /users/{id}` | Masterspezifikation | Identitaet: `{"data":{"id" oder "sub", "status":"active\|disabled\|locked\|deleted", "name", "email", "email_verified", "tenant_id", "roles":[...], "updated_at"}}`; 404/410 = geloescht. Die zurueckgegebene ID muss der angefragten entsprechen |
| `POST /auth/credentials/verify` | **Ergaenzung dieses Repos** (die Masterliste enthaelt keinen Endpunkt fuer die Zugangsdatenpruefung) | Body `{identifier, password, mfa_code?, client_ip?}` -> `{"data":{"result":"ok\|invalid\|mfa_required\|locked\|disabled", "sub"?, "amr"?}}` |

Verhalten bei Fehlern: Dash nicht erreichbar, Timeout, 5xx, fehlende/ungueltige Antwortsignatur, falsche `X-Vylaris-Key-Id` der Antwort oder unbekannte Felder -> **kein Login** (fail closed).

## 6. Token-Lebenszyklus (Service-API-Token)

| Phase | Verhalten |
|---|---|
| Ausstellung | Beim Bootstrap erzeugt log_in zwei Token: `service_token` (Dash -> log_in; log_in speichert nur den Hash) und `login_to_dash_token` (log_in -> Dash; Dash speichert den Hash, log_in haelt es mit `APP_KEY` verschluesselt). Uebergabe einmalig im Bootstrap-Bundle (0600) |
| Gueltigkeit | `SERVICE_TOKEN_TTL_DAYS` (Standard 90), Scopes, Installationsbindung |
| Rotation | `POST /service-tokens/rotate` (Scope `service.rotate`): beide neuen Token kommen als **Sealed Box** an den X25519-Schluessel von Dash (`box_public_key` aus der Discovery) - Klartext nie in der Antwort. Das neue Inbound-Token gilt ab der ersten Nutzung; das alte bleibt noch 10 Minuten (`grace`) gueltig, spaetestens 24 h. Der Wechsel des Outbound-Tokens erfolgt mit dieser ersten Nutzung (= Empfangsbestaetigung) |
| Widerruf | `php artisan login:dash:revoke-tokens` (Notfall, alle Token) oder Ersatz beim erneuten Bootstrap. Widerrufene Token -> `invalid_token`/`installation_revoked` |
| Ablauf | `token_expired`; Dash muss vor Ablauf rotieren; sonst Recovery-Link und erneuter Bootstrap |
| Audit | `service_token.issued/rotated/activated/revoked_all`; Token und Authorization-Header werden nie protokolliert |

Die Ed25519-Signaturschluessel sind getrennt: Token-Rotation ist **keine** Schluesselrotation. Rotation der Signaturschluessel (Dash <-> log_in) erfordert ein erneutes Setup/Recovery (siehe [BOOTSTRAP.md](BOOTSTRAP.md)); die OIDC-Signaturschluessel (RS256) rotieren ueber `/keys/rotate`.

## 7. SSRF-Schutz

Gilt fuer jeden ausgehenden Aufruf an Dash und fuer `base_url` bei Pairing: nur HTTPS, keine Zugangsdaten/Fragmente in der URL, keine Loopback-, privaten, Link-Local-, CGNAT-, Multicast- oder reservierten Adressen, DNS-Aufloesung wird geprueft und fuer die Verbindung festgenagelt (DNS-Rebinding), Redirects sind deaktiviert. Lockerungen (`DASH_ALLOW_HTTP`, `VYLARIS_ALLOW_PRIVATE_TARGETS`, `VYLARIS_SSRF_ENFORCE=false`) wirken **nur ausserhalb der Produktion**; in Produktion werden sie ignoriert und mit `critical` geloggt.
