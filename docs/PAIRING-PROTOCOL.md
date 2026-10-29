# Vylaris Pairing Protocol (Seite log_in)

log_in wird **nur** ueber dieses Protokoll mit Tools verknuepft. Es gibt keine zweite Verknuepfungsmethode und keine von Hand kopierten API-Keys. Das Tool spricht nur mit Dash; Dash ruft log_in auf. log_in hat keinen oeffentlichen Pairing-Endpunkt fuer Tools.

## Ablauf

| # | Schritt | Wer | log_in-Beteiligung |
|---|---|---|---|
| 1-2 | Tool gibt Dash-URL an, entdeckt und verifiziert Dash | Tool | keine |
| 3 | Dash-Administrator oeffnet Pairing-Fenster (Standard 300 s) | Dash | keine |
| 4 | Tool registriert Anfrage bei Dash und pollt ca. alle 2 s | Tool/Dash | keine |
| 5 | Dash zeigt Name, Domain, Version, Installationskennung, Scopes | Dash | `POST /pairings` (Dash legt die Anfrage bei log_in an) |
| 6 | Dash genehmigt zuerst | Dash | `POST /pairings/{id}/dash-approve` |
| 7 | Tool-Administrator bestaetigt lokal durch erneute Authentifizierung; das Tool signiert die Challenge | Tool | `POST /pairings/{id}/tool-confirm` |
| 8 | Kryptografische Nachweise werden geprueft | log_in | Signatur ueber Challenge + Parameter |
| 9 | Zugangsdaten werden eingerichtet, Integration aktiviert | log_in | Client entsteht, Secret versiegelt zurueck |

## Zustandsautomat

```
requested --dash-approve--> dash_approved --tool-confirm (Nachweis ok)--> active
requested | dash_approved --dash-reject--> rejected
requested | dash_approved --cancel-------> cancelled
requested | dash_approved --Ablauf-------> expired
dash_approved --tool-confirm (Nachweis falsch)--> failed
```

Terminal: `active`, `rejected`, `cancelled`, `expired`, `failed`. Idempotent: wiederholtes `dash-approve`/`dash-reject`/`cancel` im Zielzustand, `POST /pairings` mit gleicher `pairing_id`, `tool-confirm` im Zustand `active` (liefert dieselben versiegelten Zugangsdaten, solange nicht quittiert). Abgelaufene Pairings werden bei jedem Zugriff und per Cron (`login:maintenance`) auf `expired` gesetzt; ein Hintergrunddienst ist nicht noetig.

## Schluessel des Tools

Das Tool erzeugt pro Pairing:

- **Ed25519**-Schluesselpaar `tool_sign_public_key` (Besitznachweis),
- **X25519**-Schluesselpaar `tool_box_public_key` (Empfang der Zugangsdaten).

## `POST /api/dash/v1/pairings`

```json
{"pairing_id":"pair-<16-64 [A-Za-z0-9_-]>","installation_id":"<8-128 [A-Za-z0-9_.:-]>",
 "name":"Vylaris Tickets","domain":"tickets.example.ch","version":"1.4.0",
 "redirect_uris":["https://tickets.example.ch/auth/callback"],"post_logout_uris":["https://tickets.example.ch/"],
 "scopes":["openid","profile","email","vylaris"],
 "tool_sign_public_key":"<Base64 Ed25519>","tool_box_public_key":"<Base64 X25519>","window_seconds":300}
```

Validierung (sonst 422 `validation_failed`): `openid` ist Pflicht; nur bekannte Scopes; `domain` ist ein gueltiger Hostname; Redirect-/Logout-URIs: absolut, **HTTPS** (HTTP nur fuer `localhost` ausserhalb Produktion), kein Fragment, keine Wildcards, keine Zugangsdaten in der URL, **Host == Domain oder Subdomain davon**; max. 10 URIs; Schluessel muessen die richtige Laenge haben; `window_seconds` 30-900.
Konflikte (409): `installation_already_paired` (aktiver/gesperrter/fehlerhafter Client existiert -> zuerst trennen), `pairing_in_progress` (offenes Pairing derselben Installation), `pairing_conflict` (gleiche `pairing_id`, andere Installation).

Antwort `201`:

```json
{"pairing_id":"...","state":"requested","installation_id":"...","name":"...","domain":"...","version":"1.4.0",
 "scopes":[...],"redirect_uris":[...],"expires_at":"2026-10-29T06:15:00+00:00","dash_approved_at":null,
 "confirmed_at":null,"failure_reason":null,"challenge":"<einmalig>"}
```

`challenge` wird in den Zustaenden `requested`/`dash_approved` ausgegeben und ist **einmalig**. Dash reicht sie an das Tool weiter.

## `POST /api/dash/v1/pairings/{id}/tool-confirm`

Body: `{"proof": "<Base64 Ed25519-Signatur>"}`. Das Tool signiert mit seinem Pairing-Schluessel:

```
VYLARIS-PAIR-V1
<pairing_id>
<installation_id>
<challenge>
<SHA-256-Hex von json_encode([redirect_uris, scopes])>      # PHP-json_encode: Slashes escaped (\/), Unicode escaped
```

Der Hash bindet den Nachweis an die genehmigten Redirect-URIs und Scopes (nachtraegliche Erweiterung macht ihn ungueltig). Pruefungen: Zustand `dash_approved`, nicht abgelaufen, Challenge unbenutzt, Signatur gueltig.

- Gueltig -> Zustand `active`, Client `vl_<24 hex>` mit 256-Bit-Geheimnis (nur Hash gespeichert), `sealed_credentials` = `crypto_box_seal` (libsodium, Empfaenger: `tool_box_public_key`) ueber

  ```json
  {"issuer":"https://login.example.ch","client_id":"vl_...","client_secret":"...","token_endpoint_auth_method":"client_secret_basic"}
  ```
- Ungueltig -> Zustand `failed`, Challenge verbraucht, **kein Client**. Ein neuer Versuch braucht ein neues Pairing-Fenster.

Das Klartext-Geheimnis verlaesst log_in nie unverschluesselt und ist auch fuer Dash (Relay) nicht lesbar.

## `POST /api/dash/v1/pairings/{id}/credentials-ack`

Nach erfolgreicher Entschluesselung durch das Tool: loescht `sealed_credentials`. Ohne Quittung werden sie spaetestens nach 1 h per `login:maintenance` geloescht.

## Nach der Aktivierung

- Kachel: `GET /api/dash/v1/clients` (Status `active`).
- Geheimnisrotation: `POST /clients/{id}/rotate-secret` -> neues, wiederum versiegeltes Geheimnis; das alte bleibt 10 Minuten gueltig.
- Trennen: `POST /clients/{id}/disconnect` -> keine neuen Tokens, bestehende Access-/Refresh-Tokens sofort ungueltig, Geheimnis geloescht. Erneutes Pairing ist danach moeglich.
- Sperren/Entsperren: `suspend`/`resume`.

## Garantien

log_in **drängt Dash keine Tools auf** (es gibt keinen Endpunkt, der ohne Dash-Aufruf einen Client anlegt) und **aktiviert keine Integration ohne genehmigte Registrierung** (Client entsteht erst nach `dash-approve` + gueltigem Nachweis). Getestet in `tests/Feature/PairingTest.php`.
