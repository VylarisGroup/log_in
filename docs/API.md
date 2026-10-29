# Dash-API (beide Richtungen)

Alle Endpunkte sind **Server-zu-Server**. Es gibt keine API-Keys zum Kopieren: die Gegenstellen etablieren beim Setup je einen Ed25519-Schluessel (Fingerprint-Abgleich, siehe [BOOTSTRAP.md](BOOTSTRAP.md)).

## Signaturverfahren (`VYLARIS-V1`)

Header jeder Anfrage:

| Header | Inhalt |
|---|---|
| `X-Vylaris-Key-Id` | Installations-ID des Senders (`login-...` bzw. Dash-Installations-ID) |
| `X-Vylaris-Timestamp` | Unix-Zeit in Sekunden, Toleranz +-60 s |
| `X-Vylaris-Nonce` | 16-64 Zeichen `[A-Za-z0-9_-]`, **einmalig** (Server speichert sie 180 s) |
| `X-Vylaris-Signature` | Base64 der Ed25519-Detached-Signatur ueber den kanonischen String |

Kanonischer String (Zeilen durch `\n`, kein abschliessendes `\n`):

```
VYLARIS-V1
<METHODE grossgeschrieben>
<Pfad inkl. Query, wie gesendet, z. B. /api/dash/v1/users/u-1/revoke>
<Timestamp>
<Nonce>
<SHA-256-Hex des Request-Bodys (leer bei GET: Hash des leeren Strings)>
```

Antworten sind ebenfalls signiert (Header `X-Vylaris-Timestamp`, `X-Vylaris-Signature`) ueber:

```
VYLARIS-V1-RESP
<HTTP-Status>
<Nonce der Anfrage>
<Timestamp der Antwort>
<SHA-256-Hex des Antwort-Bodys>
```

Die Bindung an die Anfrage-Nonce verhindert Antwort-Replay. Der Empfaenger **muss** Signatur und Zeitstempel pruefen und bei Fehlern wie bei einem Ausfall reagieren.

Fehler (HTTP 401): `{"error": "bad_auth_headers" | "timestamp_out_of_range" | "bad_signature" | "replay"}`; 503 `dash_not_configured`, solange das Setup nicht abgeschlossen ist. Alle JSON-Antworten tragen `Cache-Control: no-store`.

Schluessel (Base64): `login.sign_public` / Dash-Schluessel = 32-Byte Ed25519-Public-Key.

## A. log_in -> Dash (von Dash zu implementieren)

Basis: `<dash_base_url>/api/vylaris/v1`. Rechte: genau diese vier Endpunkte, lesend, ohne Schreibzugriff auf Dash-Daten.

### `GET /discovery` (oeffentlich, **nicht** signiert)

```json
{"api_version":"1","installation_id":"<Dash-Installations-ID>","name":"Dash","public_key":"<Ed25519 Base64>"}
```

Der Schluessel ist erst nach Fingerprint-Bestaetigung vertrauenswuerdig. `api_version` muss `"1"` sein.

### `GET /log-in/health` (signiert)

Antwort `200 {"status":"ok"}`.

### `POST /log-in/credentials/verify` (signiert)

```json
{"identifier":"alice@example.test","password":"...","mfa_code":"123456","client_ip":"203.0.113.5"}
```
(`mfa_code`, `client_ip` optional.) Dash prueft Passwort **und** MFA und wendet seine Sperr-/Drosselregeln an.

| `result` | Bedeutung | Weitere Felder |
|---|---|---|
| `ok` | Anmeldung gueltig | `sub` (Pflicht, <=128 Zeichen), `amr` (z. B. `["pwd","otp"]`) |
| `invalid` | Passwort/Code falsch oder Konto unbekannt | |
| `mfa_required` | Passwort ok, MFA-Code fehlt | |
| `locked` / `disabled` | Konto gesperrt/deaktiviert | |

log_in zeigt bei `invalid`/`locked`/`disabled` **dieselbe** Meldung. HTTP-Status der Antwort ist 200; 5xx/Timeouts gelten als Ausfall.

### `GET /log-in/users/{sub}` (signiert)

```json
{"sub":"u-alice","status":"active","name":"Alice","email":"alice@example.test","email_verified":true,
 "tenant_id":"t-1","roles":["admin"],"updated_at":"2026-10-29T06:00:00Z"}
```

Pflicht: `sub` (identisch zur angefragten), `status` in `active|disabled|locked|deleted`. `roles`: Strings gemaess `^[a-z0-9][a-z0-9_.:-]{0,63}$`. `tenant_id` <=128 Zeichen oder `null`. Unbekannte/geloeschte Konten: HTTP 404 oder 410 (wird als `deleted` behandelt) oder `status: deleted`. Jede Abweichung (falsche `sub`, unbekannter `status`, ungueltige Rolle) wird als Protokollfehler abgelehnt.

Caching in log_in: aktive Konten werden hoechstens `DASH_CLAIMS_CACHE_TTL` Sekunden (Standard 60) gehalten, nicht-aktive nie.

## B. Dash -> log_in (`/api/dash/v1`, von log_in implementiert)

Nur Dash darf diese API nutzen; Reseller und Tools **nie**. Jede Anfrage wird mit dem bestaetigten Dash-Schluessel geprueft.

| Methode & Pfad | Zweck | Erfolg |
|---|---|---|
| `GET /health` | Zustand, aktive `kid` | 200 |
| `POST /pairings` | Pairing-Anfrage anlegen (idempotent) | 201 neu / 200 bekannt |
| `GET /pairings/{id}` | Zustand abfragen (Polling alle ~2 s) | 200 |
| `POST /pairings/{id}/dash-approve` | Dash-Freigabe | 200 |
| `POST /pairings/{id}/dash-reject` | Ablehnung | 200 |
| `POST /pairings/{id}/tool-confirm` | Nachweis des Tools, aktiviert Client | 200 |
| `POST /pairings/{id}/credentials-ack` | Zugangsdaten wurden uebernommen | 200 |
| `POST /pairings/{id}/cancel` | Abbruch | 200 |
| `GET /clients` | alle Clients (Kacheln) + offene Pairings | 200 |
| `GET /clients/{client_id}` | eine Kachel | 200 |
| `PATCH /clients/{client_id}` | `redirect_uris`, `post_logout_uris`, `scopes`, `version` | 200 |
| `POST /clients/{client_id}/suspend` | sperren (Tokens widerrufen) | 200 |
| `POST /clients/{client_id}/resume` | entsperren | 200 |
| `POST /clients/{client_id}/disconnect` | trennen (Tokens widerrufen, Geheimnis geloescht) | 200 |
| `POST /clients/{client_id}/report-error` | Status `error` setzen | 200 |
| `POST /clients/{client_id}/rotate-secret` | neues Geheimnis (versiegelt), altes 10 min gueltig | 200 |
| `GET /keys` | Signaturschluessel (ohne private Teile) | 200 |
| `POST /keys/rotate` | Rotation | 201 |
| `POST /keys/{kid}/revoke` | sofortiger Widerruf | 200 |
| `POST /users/{sub}/revoke` | Konto gesperrt/geloescht: Sitzungen + Tokens widerrufen; Body optional `{"reason":"..."}` | 200 `{"sub","revoked_sessions"}` |
| `POST /users/{sub}/refresh` | Rollen/Mandant geaendert: Cache invalidieren | 200 |

Fehlercodes: `not_found` (404), `validation_failed` (422, `details`), `invalid_state:<state>` (409), `dash_client_protected` (409), `installation_already_paired` / `pairing_in_progress` / `pairing_conflict` (409), `expired` (410), `proof_invalid` (422), `challenge_used` (409), `rotation_not_supported` (422).
Der Dash-Client selbst (`is_dash`) kann nicht getrennt oder gesperrt werden.

Details zu `/pairings/*`: [PAIRING-PROTOCOL.md](PAIRING-PROTOCOL.md). Beispiel-Implementierung beider Richtungen als ausfuehrbare Referenz: `tests/Support/FakeDash.php` und `tests/DashTestCase.php`.

### Kachel (`GET /clients`)

```json
{"clients":[{"client_id":"vl_...","installation_id":"...","name":"Vylaris Tickets","domain":"tickets.example.ch","version":"1.4.0",
  "status":"active","confidential":true,"redirect_uris":["..."],"post_logout_uris":["..."],"scopes":["openid","vylaris"],
  "last_error":null,"updated_at":"2026-10-29T06:00:00+00:00"}],
 "pending_pairings":[{"pairing_id":"...","installation_id":"...","name":"...","domain":"...","status":"pending","state":"requested"}]}
```

`status`: `pending` (nur in `pending_pairings`), `active`, `error`, `suspended`, `disconnected`.
