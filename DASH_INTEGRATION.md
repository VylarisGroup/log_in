# DASH_INTEGRATION - Briefing fuer die Code-KI, die Dash baut

Dieses Dokument beschreibt **ausschliesslich real implementierte** Schnittstellen von Vylaris log_in (Version 1.0.0). Nichts davon ist Platzhalter. Massgeblich im Zweifel: `docs/API.md`, `docs/PAIRING-PROTOCOL.md`, `docs/OIDC.md` und der ausfuehrbare Referenzcode `tests/Support/FakeDash.php`, `app/Services/Vylaris/Signer.php`.

Architektur: `Reseller <-> Dash <-> log_in <-> Tools`. Dash ist die Quelle der Wahrheit fuer Konten, Mandanten, Rollen, Status und MFA. log_in hat **keinen** Zugriff auf die Dash-Datenbank und besitzt keine Konten. log_in laeuft nicht standalone.

## 1. Was Dash bauen muss

| # | Aufgabe |
|---|---|
| 1 | **Vier Endpunkte** unter `/api/vylaris/v1` (Abschnitt 3), die log_in aufruft |
| 2 | **Ed25519-Schluesselpaar** fuer Dash; Antworten signieren, Anfragen von log_in verifizieren |
| 3 | **Client der log_in-Verwaltungs-API** `/api/dash/v1/*` (Abschnitt 4) fuer Pairing, Kacheln, Sperren, Schluessel, Widerruf |
| 4 | **OIDC-Relying-Party** gegen log_in (Dash meldet seine Benutzer ueber log_in an) |
| 5 | **Push bei Rechteentzug**: `POST /api/dash/v1/users/{sub}/revoke` bzw. `/refresh` |
| 6 | **Kacheln** fuer integrierte Tools aus `GET /clients` (Abschnitt 6) |
| 7 | **Pairing-Oberflaeche** und Relay zwischen Tool und log_in (Abschnitt 5) |

## 2. Signaturverfahren (beide Richtungen)

Bibliothek: libsodium (`sodium_crypto_sign_detached`, `sodium_crypto_sign_verify_detached`). Schluessel und Signaturen **Base64 (Standard-Alphabet)**; Public Key 32 Byte.

Request-Header: `X-Vylaris-Key-Id`, `X-Vylaris-Timestamp` (Unix-Sekunden), `X-Vylaris-Nonce` (16-64 Zeichen `[A-Za-z0-9_-]`, einmalig), `X-Vylaris-Signature`.

```
canonical_request = "VYLARIS-V1\n" . STRTOUPPER(method) . "\n" . path_with_query . "\n" . timestamp . "\n" . nonce . "\n" . sha256_hex(raw_body)
signature = base64( ed25519_detached(canonical_request, sender_secret) )
```

Die Antwort traegt `X-Vylaris-Timestamp` und `X-Vylaris-Signature` ueber

```
canonical_response = "VYLARIS-V1-RESP\n" . status . "\n" . request_nonce . "\n" . response_timestamp . "\n" . sha256_hex(raw_response_body)
```

Regeln: Zeitabweichung <= 60 s; Nonces nur einmal akzeptieren (mindestens 180 s merken); Pfad exakt wie gesendet (inkl. Query); Body nicht nachtraeglich umformatieren. Eine Dash-Antwort **ohne gueltige Signatur wird von log_in wie ein Ausfall behandelt** (Anmeldung scheitert).

PHP-Referenz (aus `Signer.php`):

```php
$sig = base64_encode(sodium_crypto_sign_detached($canonical, base64_decode($secretKeyB64)));
$ok  = sodium_crypto_sign_verify_detached(base64_decode($sig), $canonical, base64_decode($publicKeyB64));
```

## 3. Endpunkte, die Dash implementieren muss (log_in -> Dash)

Basis `<dash>/api/vylaris/v1`. Details und Feldregeln: `docs/API.md` Abschnitt A.

| Methode & Pfad | Signiert | Antwort |
|---|---|---|
| `GET /discovery` | nein | `{"api_version":"1","installation_id":"...","name":"Dash","public_key":"<Ed25519 b64>"}` |
| `GET /log-in/health` | ja | `200 {"status":"ok"}` |
| `POST /log-in/credentials/verify` | ja | Body `{"identifier","password","mfa_code"?,"client_ip"?}` -> `{"result":"ok","sub":"...","amr":["pwd","otp"]}` oder `{"result":"invalid"\|"mfa_required"\|"locked"\|"disabled"}` |
| `GET /log-in/users/{sub}` | ja | `{"sub","status":"active\|disabled\|locked\|deleted","name","email","email_verified","tenant_id","roles":[],"updated_at"}`; unbekannt: 404/410 |

Anforderungen: Passwort **und** MFA prueft Dash; Sperrung/Drosselung bleibt bei Dash; `sub` ist stabil und unveraenderlich; `roles` passen auf `^[a-z0-9][a-z0-9_.:-]{0,63}$`; Antworten in unter 5 s (Timeout in log_in: 5 s, Verbindung 3 s).

## 4. Verwaltungs-API von log_in (Dash -> log_in)

Basis `<issuer>/api/dash/v1`, jede Anfrage signiert mit dem Dash-Schluessel (`X-Vylaris-Key-Id` = Dash-Installations-ID). Vollstaendige Liste mit Erfolgscodes und Fehlern in `docs/API.md` Abschnitt B:

`GET /health` - `POST /pairings` - `GET /pairings/{id}` - `POST /pairings/{id}/{dash-approve|dash-reject|cancel|tool-confirm|credentials-ack}` - `GET /clients` - `GET|PATCH /clients/{client_id}` - `POST /clients/{client_id}/{suspend|resume|disconnect|report-error|rotate-secret}` - `GET /keys` - `POST /keys/rotate` - `POST /keys/{kid}/revoke` - `POST /users/{sub}/revoke` - `POST /users/{sub}/refresh`.

**Wann Dash `users/{sub}/revoke` aufruft:** Konto gesperrt, deaktiviert, geloescht, Passwort/MFA zurueckgesetzt, Mandantenzugehoerigkeit entzogen. **`users/{sub}/refresh`:** Rollen oder Mandant geaendert (leert den Identitaets-Cache).

## 5. Pairing (Tool <-> Dash <-> log_in)

Vollstaendige Beschreibung: `docs/PAIRING-PROTOCOL.md`. Dash-Rolle:

1. Administrator oeffnet Pairing-Fenster (Standard 300 s, 30-900 s).
2. Tool registriert sich bei Dash (Name, Domain, Version, Installationskennung, Redirect-/Logout-URIs, Scopes, `tool_sign_public_key` Ed25519, `tool_box_public_key` X25519). Das Tool-zu-Dash-Protokoll definiert Dash selbst; log_in verlangt nur die Felder aus Schritt 3.
3. Dash zeigt die Anfrage zur Freigabe und ruft `POST /pairings` auf (liefert `challenge`).
4. Dash genehmigt zuerst: `POST /pairings/{id}/dash-approve`.
5. Dash gibt dem Tool die `challenge`; das Tool bestaetigt lokal und signiert

   ```
   "VYLARIS-PAIR-V1\n" . pairing_id . "\n" . installation_id . "\n" . challenge . "\n" . sha256_hex(json_encode([redirect_uris, scopes]))
   ```
   (PHP-`json_encode` mit Standard-Flags: Slashes werden als `\/` ausgegeben; wer nicht in PHP baut, muss exakt dieselbe Zeichenkette erzeugen: kompaktes JSON, `/` als `\/`, Nicht-ASCII als `\uXXXX`.)
6. Dash leitet den Nachweis weiter: `POST /pairings/{id}/tool-confirm` mit `{"proof": "<b64>"}`. Antwort enthaelt `sealed_credentials` (libsodium `crypto_box_seal` an den X25519-Schluessel des Tools). **Dash kann das Geheimnis nicht lesen** und reicht es nur durch.
7. Tool entschluesselt, Dash ruft `POST /pairings/{id}/credentials-ack`.

Dash darf nie Client-Geheimnisse selbst erzeugen oder speichern. Es gibt keinen Weg, Clients anders anzulegen.

## 6. Kacheln

`GET /clients` liefert `clients[]` (Status `active|error|suspended|disconnected`) und `pending_pairings[]`. Darstellung: Name, Domain, Version, Status, `last_error`. Aktionen je Kachel: Sperren (`suspend`), Entsperren (`resume`), Trennen (`disconnect`, nicht fuer den Dash-Client), Geheimnis rotieren, Fehler melden. Fuer die Kachel von Dash selbst ist `is_dash` gesetzt; sie ist geschuetzt (`409 dash_client_protected`).

## 7. Bootstrap (Erstverbindung)

Ablauf in `docs/BOOTSTRAP.md`. Dash-relevant:

1. Dash stellt `GET /api/vylaris/v1/discovery` bereit und **zeigt den Fingerprint seines Schluessels an** (Berechnung: `Signer::fingerprint`, siehe unten).
2. Der Betreiber vergleicht ihn im log_in-Setup und tippt ihn ein.
3. log_in schreibt `storage/app/bootstrap/dash-bootstrap.json` (0600):

```json
{
  "schema": "vylaris-login-bootstrap/1",
  "issuer": "https://login.example.ch",
  "discovery_url": "https://login.example.ch/.well-known/openid-configuration",
  "client_id": "vl_dash_<16 hex>",
  "client_secret": "<43 Zeichen base64url>",
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": ["https://dash.example.ch/..."],
  "post_logout_uris": ["https://dash.example.ch/..."],
  "scopes": ["openid","profile","email","vylaris","offline_access"],
  "log_in_installation_id": "...",
  "log_in_public_key": "<Ed25519 b64>",
  "log_in_public_key_fingerprint": "AB12:CD34:...",
  "log_in_api_base": "https://login.example.ch/api/dash/v1",
  "created_at": "2026-10-29T06:00:00+00:00"
}
```
4. Dash importiert den log_in-Schluessel **nach Abgleich des Fingerprints**, legt den OIDC-Client an und verwendet `log_in_installation_id` als Erwartung fuer `X-Vylaris-Key-Id`.
5. Beim ersten erfolgreichen OIDC-Code-Austausch von Dash schaltet log_in den Setup-Admin ab und loescht das Bundle. Dash muss das Bundle spaetestens bis dahin eingelesen haben.

Fingerprint: SHA-256 ueber die rohen 32 Public-Key-Bytes, Hex, nur die ersten 32 Hex-Zeichen, gross geschrieben, in Vierergruppen mit `:` getrennt (z. B. `AB12:CD34:...`, 8 Gruppen). Beim Vergleich zaehlen nur die Hex-Ziffern (Trennzeichen und Gross-/Kleinschreibung egal). Massgeblich ist `Signer::fingerprint`.

## 8. OIDC fuer Dash selbst

Dash ist ein normaler vertraulicher Client: Authorization Code + **PKCE S256 (Pflicht)**, `state` und `nonce` **Pflicht**, Redirect-URIs exakt wie registriert, Scopes `openid profile email vylaris offline_access`. Validierung des ID-Tokens: RS256 via JWKS (`kid`), `iss`, `aud`, `exp`, `nonce`, `at_hash`. Details: `docs/OIDC.md`. Rollenwerte (`roles`) und `tenant_id` stammen aus Dash selbst und werden nur gespiegelt.

## 9. Ausfall- und Fehlerverhalten, das Dash kennen muss

- Ist Dash nicht erreichbar oder antwortet unsigniert: **keine Anmeldungen**, keine Token-Erneuerung. Das ist beabsichtigt.
- Kontostatus wird bei Refresh immer frisch geholt, sonst hoechstens 60 s zwischengespeichert. Fuer sofortige Wirkung `users/{sub}/revoke` senden.
- Dash sollte `log_in/health` periodisch aufrufen und `GET /api/dash/v1/health` fuer die eigene Statusanzeige nutzen.

## 10. Abnahme (Dash-Seite)

| Pruefung | Erwartung |
|---|---|
| Discovery liefert Schluessel, Fingerprint stimmt | Setup von log_in akzeptiert |
| `log-in/health` signiert | Verbindungstest in log_in besteht |
| Anmeldung mit Passwort + MFA | `credentials/verify` -> `ok`, Tool erhaelt ID-Token mit `sub`, `roles`, `tenant_id` |
| Konto sperren + `users/{sub}/revoke` | UserInfo/Refresh der Tools scheitern sofort |
| Dash stoppen | Anmeldung scheitert mit "nicht verfuegbar", keine Freigabe aus Cache nach > 60 s |
| Pairing durchspielen | Client erscheint als Kachel `active`; Trennen -> Tokens ungueltig |
| Replay einer signierten Anfrage | `401 replay` |
| Zeitabweichung > 60 s | `401 timestamp_out_of_range` |

`FakeDash` in `tests/Support/FakeDash.php` ist ein funktionierendes Beispiel der Dash-Seite von Abschnitt 3 und kann als Vorlage dienen. Dash selbst und der Test gegen ein reales Dash sind **nicht Teil dieses Repositories und noch nicht ausgefuehrt** (siehe `docs/SECURITY.md`, Offene Punkte).
