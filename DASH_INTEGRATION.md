# DASH_INTEGRATION - Briefing fuer die Code-KI, die Dash baut

Gilt fuer **Vylaris log_in 1.1.0** und folgt dem gemeinsamen "Master Implementation Prompt - Vylaris Unified API". Beschrieben ist ausschliesslich, was in log_in real implementiert und getestet ist. Massgeblich im Zweifel: `docs/openapi.yaml`, `docs/test-vectors.json`, `docs/API.md`, `docs/PAIRING-PROTOCOL.md`, der Code (`app/Services/Vylaris/Signer.php`, `app/Http/Middleware/VerifyMachineRequest.php`) und das Referenz-Dash `tests/Support/FakeDash.php`.

Architektur: `Reseller -> Dash <-> log_in -> OIDC-Clients/Tools`. Dash ist die Quelle der Wahrheit fuer Konten, Mandanten, Rollen, MFA, Tool-Installationen. log_in hat keinen Zugriff auf die Dash-Datenbank, besitzt keine Konten und laeuft nicht ohne Dash. Reseller spricht nie mit log_in.

## 1. Aufgaben von Dash

| # | Aufgabe |
|---|---|
| 1 | Discovery `GET /.well-known/vylaris-dash` (unsigniert) |
| 2 | Vier Endpunkte unter `/api/vylaris/v1`, die log_in aufruft (Abschnitt 4) |
| 3 | Ed25519-Schluesselpaar + X25519-Schluesselpaar fuer Dash; Antworten signieren, Anfragen von log_in pruefen |
| 4 | Client fuer die log_in-Verwaltungs-API (Abschnitt 5) mit Bearer-Token + Signatur |
| 5 | OIDC-Relying-Party gegen log_in (Dash meldet seine Benutzer ueber log_in an) |
| 6 | Pairing-Oberflaeche (Fenster, Genehmigung, Relay) und Kacheln aus `GET /clients` |
| 7 | Push bei Rechteentzug: `POST /users/{sub}/revoke` bzw. `/refresh` |
| 8 | Token-Rotation des Service-Tokens vor Ablauf (`POST /service-tokens/rotate`) |

## 2. Gemeinsame Konventionen (identisch in allen Projekten)

* API-Version `v1`, Pfadraum **`/api/vylaris/v1`** fuer Dash und log_in. Keine Alt-Pfade (`/api/dash/v1`, `/log-in/*`, `/api/v1/tools/*`) - log_in antwortet darauf mit 404.
* Header: `Authorization: Bearer <token>`, `X-Vylaris-Key-Id`, `X-Vylaris-Timestamp`, `X-Vylaris-Nonce`, `X-Vylaris-Signature`. Optional `Idempotency-Key` bei schreibenden Aufrufen.
* Ed25519 via libsodium; Schluessel und Signaturen Base64 (Standardalphabet), Public Key 32 Byte.
* Request-Signatur (Strings, kein abschliessendes `\n`):
  `VYLARIS-V1\n<METHOD>\n<PATH_AND_QUERY>\n<TIMESTAMP>\n<NONCE>\n<sha256_hex(raw body)>`
* Antwort-Signatur (Header `X-Vylaris-Key-Id`, `X-Vylaris-Timestamp`, `X-Vylaris-Signature`):
  `VYLARIS-V1-RESP\n<STATUS>\n<REQUEST_NONCE>\n<RESPONSE_TIMESTAMP>\n<sha256_hex(raw body)>`
* Testvektoren: `docs/test-vectors.json` (deterministisch, Ed25519). Jeder Signer/Verifier in Dash **muss** diese Vektoren exakt reproduzieren.
* Zeitfenster +-60 s; Nonce pro Installation einmalig, mind. 180 s speichern.
* Antworten: `{"data":{...}}`, Listen `{"data":[...],"meta":{...}}`, Fehler `{"error":{"code","message","details"?}}`. Codes: `unauthorized, invalid_token, token_expired, invalid_signature, timestamp_out_of_range, replay_detected, forbidden, pairing_closed, pairing_expired, pairing_denied, invalid_pairing_proof, installation_revoked, resource_not_found, duplicate_conflict, idempotency_conflict, validation_failed, rate_limited, service_unavailable, internal_error`.
* Ausnahmen von der Antwortsignatur (unsigniert): Discovery-Endpunkte und OIDC-Metadaten.

## 3. Token (nur Service-API-Token zwischen Dash und log_in)

| Richtung | Token im Bundle | Wer speichert wie |
|---|---|---|
| Dash -> log_in | `service_token` | log_in: nur SHA-256-Hash. Dash: sicher ablegen, **nie loggen** |
| log_in -> Dash | `login_to_dash_token` | Dash: nur SHA-256-Hash (Token hat 256 Bit Entropie) und pro Request vergleichen |

Format `vlst_<base64url>`; Scopes `service.health, pairings.manage, clients.read, clients.manage, keys.manage, users.revoke, service.rotate` (Bundle: `service_token_scopes`); Ablauf `service_token_expires_at` (Standard 90 Tage). OIDC-Access-Tokens und Tool-API-Tokens werden von log_in **nicht** als Service-Token akzeptiert und umgekehrt.

**Rotation:** `POST /service-tokens/rotate` -> `data.sealed_tokens` = libsodium Sealed Box (an `box_public_key` aus **Dash-Discovery**; ohne diesen Schluessel liefert log_in `validation_failed`) mit JSON `{"service_token","login_to_dash_token","service_token_expires_at"}`. Dash oeffnet sie, speichert den Hash des neuen `login_to_dash_token` **bevor** es das neue `service_token` das erste Mal benutzt (die erste Nutzung schaltet bei log_in den Wechsel um), und akzeptiert danach ca. 10 Minuten beide Outbound-Token von log_in.

## 4. Was Dash fuer log_in bereitstellen muss (log_in -> Dash)

Basis `<dash>/api/vylaris/v1`; log_in sendet Bearer `login_to_dash_token`, `X-Vylaris-Key-Id` = log_in-Installations-ID, Signatur mit dem log_in-Schluessel. Dash signiert Antworten mit seinem Schluessel und setzt `X-Vylaris-Key-Id` = eigene Installations-ID (log_in prueft das).

| Methode & Pfad | Signiert | Inhalt |
|---|---|---|
| `GET /.well-known/vylaris-dash` | nein | `{"data":{"api_version":"v1","installation_id":"...","name":"Dash","public_key":"<Ed25519 b64>","box_public_key":"<X25519 b64>"}}` (`box_public_key` Pflicht fuer Token-Rotation) |
| `GET /health` | ja | `{"data":{"status":"ok"}}` |
| `GET /users/{id}` | ja | `{"data":{"id":"u-1","status":"active\|disabled\|locked\|deleted","name":"...","email":"...","email_verified":true,"tenant_id":"t-1","roles":["admin"],"updated_at":"..."}}`; `sub` wird als Alias fuer `id` akzeptiert. Antwort-ID muss exakt der angefragten entsprechen. Rollen: `^[a-z0-9][a-z0-9_.:-]{0,63}$`. 404/410 = geloescht |
| `POST /auth/credentials/verify` | ja | Body `{"identifier","password","mfa_code"?,"client_ip"?}` -> `{"data":{"result":"ok","sub":"u-1","amr":["pwd","otp"]}}` oder `result` = `invalid` / `mfa_required` / `locked` / `disabled` |

**Wichtig - Luecke der Masterliste:** Fuer die Zugangsdatenpruefung nennt die gemeinsame Spezifikation keinen Endpunkt; `POST /auth/credentials/verify` ist die Festlegung von log_in. Falls Dash dafuer bereits einen anderen Pfad/ein anderes Schema umgesetzt hat, muss **eine** Seite angepasst werden (bei log_in zentral in `DashClient::verifyCredentials`). Ebenso ist die Form von `GET /users/{id}` (Feldnamen `status`, `roles`, `tenant_id`, `email_verified`) von log_in festgelegt, weil die Spezifikation das Schema nicht vorgibt. Beides ist noch **nicht gegen ein echtes Dash getestet**.

Dash prueft Passwort und MFA, Drosselung und Sperrung. log_in speichert weder Passwort noch Code. Ist Dash nicht erreichbar, antwortet unsigniert/mit falscher Key-Id oder mit unbekanntem Schema, scheitert die Anmeldung (fail closed).

## 5. Verwaltungs-API von log_in (Dash -> log_in)

Basis `<issuer>/api/vylaris/v1`. Siehe `docs/openapi.yaml`. Kurzfassung:

`GET /health` - `GET|POST|DELETE /pairing-window` - `POST /pairings` - `GET /pairings/{id}` - `POST /pairings/{id}/{approve|reject|cancel|confirm|credentials-ack}` - `GET /clients` - `GET|PATCH /clients/{client_id}` - `POST /clients/{client_id}/{suspend|resume|disconnect|report-error|rotate-secret}` - `GET /keys` - `POST /keys/rotate` - `POST /keys/{key_id}/revoke` - `POST /users/{sub}/revoke` - `POST /users/{sub}/refresh` - `POST /service-tokens/rotate` - Discovery `GET /discovery`.

`users/{sub}/revoke`: Konto gesperrt/deaktiviert/geloescht, Passwort/MFA zurueckgesetzt, Mandantenzugang entzogen. `users/{sub}/refresh`: Rollen/Mandant geaendert.

## 6. Pairing (Dash-Rolle)

Details: `docs/PAIRING-PROTOCOL.md`.

1. Admin oeffnet Fenster: `POST /pairing-window {"duration_seconds":300}` (30-900). Ohne Fenster liefert `POST /pairings` `409 pairing_closed`.
2. Dash nimmt die Tool-Registrierung entgegen (Tool-ID, Name, Version, `base_url`, Installations-ID, Ed25519- und X25519-Schluessel, Redirect-/Logout-URIs, angeforderte Scopes) und ruft `POST /pairings` auf; Antwort enthaelt die einmalige `challenge`.
3. Admin genehmigt ausdruecklich: `POST /pairings/{id}/approve {"approved_scopes":[...]}` (Teilmenge der angeforderten, inkl. `openid`).
4. Das Tool bestaetigt lokal und signiert den **kanonischen Nachweis**:

```
VYLARIS-PAIR-V1
<pairing_id>
<installation_id>
<tool_id>
<challenge>
<base_url>
sha256_hex(sorted redirect_uris, joined with "\n")
sha256_hex(sorted post_logout_uris, joined with "\n")
sha256_hex(sorted approved_scopes, joined with " ")
```
(9 Zeilen, durch `\n` getrennt, kein abschliessender Zeilenumbruch; Vektor `pairing_proof` in `docs/test-vectors.json`.)

5. Dash leitet `{"proof":"<b64>"}` an `POST /pairings/{id}/confirm` weiter und reicht `data.sealed_credentials` (Sealed Box fuer den X25519-Schluessel des Tools) **unveraendert** an das Tool. Dash kann sie nicht lesen und darf sie nicht speichern.
6. Nach Entschluesselung durch das Tool: `POST /pairings/{id}/credentials-ack`.

## 7. Bootstrap (Erstverbindung ohne Vertrauensbeziehung)

Ablauf: `docs/BOOTSTRAP.md`. Dash-relevant:

1. Dash zeigt den **Fingerprint** seines Ed25519-Schluessels an: erste 32 Hex-Zeichen von SHA-256 ueber die 32 Public-Key-Bytes, gross, in Vierergruppen mit `:` (z. B. `AB12:CD34:...`, `Signer::fingerprint`).
2. Der Betreiber tippt ihn im log_in-Setup ein; log_in entdeckt Dash per `/.well-known/vylaris-dash` und vertraut erst bei Uebereinstimmung.
3. log_in schreibt `storage/app/bootstrap/dash-bootstrap.json` (0600, `schema: vylaris-login-bootstrap/2`):

```json
{
  "schema": "vylaris-login-bootstrap/2",
  "issuer": "https://login.example.ch",
  "discovery_url": "https://login.example.ch/.well-known/openid-configuration",
  "discovery_url_vylaris": "https://login.example.ch/.well-known/vylaris-login",
  "api_version": "v1",
  "api_base": "https://login.example.ch/api/vylaris/v1",
  "client_id": "vl_dash_<16 hex>",
  "client_secret": "<base64url>",
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": ["https://dash.example.ch/..."],
  "post_logout_uris": ["https://dash.example.ch/..."],
  "scopes": ["openid","profile","email","vylaris","offline_access"],
  "log_in_installation_id": "...",
  "log_in_public_key": "<Ed25519 b64>",
  "log_in_public_key_fingerprint": "AB12:CD34:...",
  "service_token": "vlst_...",
  "login_to_dash_token": "vlst_...",
  "service_token_scopes": ["service.health", "pairings.manage", "..."],
  "service_token_expires_at": "2026-...",
  "created_at": "2026-..."
}
```
4. Dash importiert den log_in-Schluessel **nach Fingerprint-Abgleich**, legt den OIDC-Client an, speichert `service_token` (zum Senden) und den Hash von `login_to_dash_token` (zum Pruefen) und erwartet `log_in_installation_id` als `X-Vylaris-Key-Id`.
5. Beim ersten erfolgreichen OIDC-Code-Austausch von Dash wird der Setup-Admin abgeschaltet und das Bundle geloescht. Dash muss das Bundle bis dahin gelesen haben. Danach gelten ausschliesslich regulaere Token, Signaturen, Rotation und Widerruf.

Die Uebergabe des Bundles (Datei mit 0600) erfolgt durch den Betreiber; ein oeffentlicher Endpunkt dafuer existiert bewusst nicht.

## 8. OIDC fuer Dash

Vertraulicher Client: Authorization Code + **PKCE S256**, `state` und `nonce` Pflicht, exakte Redirect-URIs, Scopes `openid profile email vylaris offline_access`. ID-Token validieren: RS256 per JWKS (`kid`), `iss`, `aud`, `exp`, `nonce`, `at_hash`. Details `docs/OIDC.md`. Der Dash-Client ist geschuetzt (kann nicht getrennt/gesperrt werden).

## 9. Ausfall- und Fehlerverhalten

* Dash nicht erreichbar / unsignierte oder falsch signierte Antwort / falsche Key-Id / Schemafehler: **keine Anmeldung, keine Token-Erneuerung**.
* Kontostatus wird bei Refresh immer frisch geholt, sonst maximal 60 s gecacht; fuer sofortige Wirkung `users/{sub}/revoke` senden.
* Outbound-Aufrufe von log_in: nur HTTPS, keine privaten/Loopback-Ziele, DNS festgenagelt, keine Redirects (`docs/API.md`, Abschnitt 7). Dash muss also unter einer oeffentlich aufloesbaren HTTPS-URL erreichbar sein (Entwicklung: `VYLARIS_ALLOW_PRIVATE_TARGETS`, wirkt nie in Produktion).

## 10. Abnahme (Dash-Seite)

| Pruefung | Erwartung |
|---|---|
| `docs/test-vectors.json` | alle Request-/Response-/Pairing-Vektoren exakt reproduziert |
| Discovery + Fingerprint | log_in-Setup akzeptiert. log_in liest `public_key` oder den ersten aktiven Ed25519-Eintrag aus `keys[]` (base64/base64url), `api_version` (`v1`/`1` oder aus `api_base`), optional `box_public_key` sowie die Hinweise `oidc_redirect_uris` und `oidc_post_logout_uris` fuer die automatische Registrierung (Standard sonst `<dash>/auth/callback`, `<dash>/`). Fehlende Felder werden im Setup namentlich gemeldet |
| `GET /health` signiert mit Bearer | log_in-Verbindungstest besteht |
| Anmeldung Passwort + MFA | `ok` -> Tool erhaelt ID-Token mit `sub`, `roles`, `tenant_id` |
| Konto sperren + `users/{sub}/revoke` | UserInfo/Refresh der Tools scheitern sofort |
| Dash stoppen | Anmeldung scheitert, keine Freigabe aus Cache nach > 60 s |
| Pairing ohne Fenster | `409 pairing_closed` |
| Pairing mit Teil-Genehmigung | Client hat nur die genehmigten Scopes |
| Falscher Nachweis | `422 invalid_pairing_proof`, kein Client |
| Request ohne Bearer / ohne Signatur / mit OIDC-Token als Bearer | 401 `unauthorized` / `invalid_signature` / `invalid_token` |
| Replay / > 60 s | `replay_detected` / `timestamp_out_of_range` |
| Token-Rotation | `sealed_tokens` laesst sich oeffnen, Wechsel nach erster Nutzung |

**Noch nicht ausgefuehrt:** Tests gegen ein echtes Dash und gegen Reseller (nicht Teil dieses Repositories). Die Contract-Tests von log_in laufen gegen `FakeDash` mit den gemeinsamen Vektoren (siehe `docs/SECURITY.md`, Offene Punkte).
