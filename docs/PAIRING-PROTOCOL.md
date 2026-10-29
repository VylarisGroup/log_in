# Vylaris Pairing Protocol (Seite log_in)

Einheitlich fuer Dash, log_in und Tools. log_in wird **nur** ueber dieses Protokoll mit Tools verknuepft; es gibt keine zweite Methode und keine von Hand kopierten API-Keys. Das Tool spricht nur mit Dash, Dash ruft log_in auf (`/api/vylaris/v1`, Bearer + Signatur, siehe [API.md](API.md)). Maschinenlesbar: [openapi.yaml](openapi.yaml), Vektor: [test-vectors.json](test-vectors.json) (`pairing_proof`).

## Ablauf

| # | Schritt | Wer | log_in-Aufruf |
|---|---|---|---|
| 1 | Dash-Administrator oeffnet das Pairing-Fenster (30-900 s, Standard 300 s) | Dash | `POST /pairing-window` |
| 2 | Tool registriert sich bei Dash und pollt; Dash zeigt Tool-ID, Name, Version, Basis-URL, Installations-ID, angeforderte Scopes | Tool/Dash | - |
| 3 | Dash legt die Anfrage bei log_in an | Dash | `POST /pairings` (ohne offenes Fenster: `pairing_closed`) |
| 4 | Dash-Administrator genehmigt ausdruecklich eine Teilmenge der Scopes | Dash | `POST /pairings/{id}/approve` |
| 5 | Tool-Administrator bestaetigt lokal (erneute Authentifizierung) und signiert den Nachweis | Tool | - |
| 6 | Dash leitet den Nachweis weiter, log_in prueft ihn und aktiviert | Dash | `POST /pairings/{id}/confirm` |
| 7 | Tool entschluesselt `sealed_credentials`; Dash meldet den Empfang | Tool/Dash | `POST /pairings/{id}/credentials-ack` |

Das Pairing gilt erst nach Nachweis (6), Entschluesselung und Empfangsbestaetigung (7) als abgeschlossen; der Client ist ab (6) aktiv, die versiegelten Zugangsdaten werden mit (7) geloescht (spaetestens nach 1 h per `login:maintenance`). Jede Genehmigung, Ablehnung, Aktivierung und jedes Oeffnen/Schliessen des Fensters wird im Audit-Log protokolliert.

## Zustandsautomat

```
requested --approve--> dash_approved --confirm (Nachweis ok)--> active
requested | dash_approved --reject--> rejected
requested | dash_approved --cancel--> cancelled
requested | dash_approved --Ablauf--> expired
dash_approved --confirm (Nachweis falsch)--> failed
```

Terminal: `active`, `rejected`, `cancelled`, `expired`, `failed`. Abgelaufene oder abgelehnte Pairings koennen nie aktiviert werden. Idempotent: `approve`/`reject`/`cancel` im Zielzustand, `POST /pairings` mit gleicher `pairing_id`, `confirm` im Zustand `active` (gleiche versiegelte Antwort bis zur Quittung). Das Ablaufdatum eines Pairings ist das **Ende des Fensters**, in dem es angelegt wurde.

## Schluessel des Tools

Pro Pairing: **Ed25519** `tool_sign_public_key` (Besitznachweis) und **X25519** `tool_box_public_key` (Empfang der Zugangsdaten). Base64 (Standardalphabet), je 32 Byte.

## `POST /pairings`

```json
{"pairing_id":"pair-<16-64 [A-Za-z0-9_-]>","installation_id":"<8-128 [A-Za-z0-9_.:-]>","tool_id":"vylaris-tickets",
 "name":"Vylaris Tickets","version":"1.4.0","base_url":"https://tickets.example.ch",
 "redirect_uris":["https://tickets.example.ch/auth/callback"],"post_logout_uris":["https://tickets.example.ch/"],
 "scopes":["openid","profile","email","vylaris"],
 "tool_sign_public_key":"<b64>","tool_box_public_key":"<b64>"}
```

Validierung (sonst 422 `validation_failed`): `tool_id` `^[a-z0-9][a-z0-9_.-]{1,63}$`; `openid` Pflicht; nur bekannte Scopes; `base_url` HTTPS, ohne Zugangsdaten/Fragment, keine privaten/Loopback-Literale; Redirect-/Logout-URIs absolut, HTTPS, ohne Fragment/Wildcard/Zugangsdaten, **Host == Host der `base_url` oder Subdomain**; max. 10 URIs; Schluessellaengen. Konflikte (409 `duplicate_conflict`, `details.reason`): `installation_already_paired`, `pairing_in_progress`, `pairing_conflict`. Antwort `201 {"data":{...,"challenge":"<einmalig>"}}`; die `challenge` wird in den Zustaenden `requested`/`dash_approved` ausgegeben und von Dash an das Tool weitergereicht.

## Genehmigung

`POST /pairings/{id}/approve` mit `{"approved_scopes":["openid","profile"]}`. Pflicht: nicht leer, enthaelt `openid`, Teilmenge der **angeforderten** Scopes (sonst 422). **Angeforderte Berechtigungen gelten nie automatisch als genehmigt.** Der OIDC-Client erhaelt genau die genehmigten Scopes.

## Kanonischer Nachweis (`VYLARIS-PAIR-V1`)

Sprachneutral, ohne JSON-Serialisierung, ohne abschliessenden Zeilenumbruch:

```
VYLARIS-PAIR-V1
<pairing_id>
<installation_id>
<tool_id>
<challenge>
<base_url>                                   (ohne abschliessenden Slash)
sha256_hex( redirect_uris, Bytereihenfolge sortiert, mit "\n" verbunden )
sha256_hex( post_logout_uris, sortiert, mit "\n" verbunden )     (leere Liste = sha256 des leeren Strings)
sha256_hex( genehmigte Scopes, sortiert, mit " " verbunden )
```

Signatur: Ed25519 mit dem privaten Pairing-Schluessel des Tools, Base64 -> `{"proof": "..."}`. Der Nachweis bindet Challenge, Installation, Tool, Basis-URL, URIs und die **genehmigten** Scopes; nachtraegliche Aenderungen machen ihn ungueltig. Pruefungen in log_in: Zustand `dash_approved`, nicht abgelaufen, Challenge unbenutzt, Signatur gueltig.

- Gueltig -> `active`, Client `vl_<24 hex>` mit 256-Bit-Geheimnis (nur Hash gespeichert). `sealed_credentials` = libsodium `crypto_box_seal` an `tool_box_public_key` ueber `{"issuer","client_id","client_secret","token_endpoint_auth_method":"client_secret_basic"}`.
- Ungueltig -> `failed`, Challenge verbraucht (`invalid_pairing_proof`, 422), **kein Client**; ein weiterer Versuch braucht ein neues Pairing.

Dash kann das Geheimnis nicht lesen (Sealed Box) und speichert es nicht.

## Nach der Aktivierung

Kachel: `GET /clients`. Geheimnisrotation: `POST /clients/{id}/rotate-secret` (versiegelt, altes 10 min gueltig). Trennen: `.../disconnect` (Tokens sofort ungueltig, Geheimnis geloescht, erneutes Pairing moeglich). Sperren/Entsperren: `suspend`/`resume`. Fehler siehe [API.md](API.md) Abschnitt 3.

## Garantien

log_in legt Clients **ausschliesslich** ueber `confirm` an, nie ohne offenes Fenster, nie ohne ausdrueckliche Genehmigung durch Dash und gueltigen Nachweis. Getestet in `PairingTest` (inkl. Fenster, Genehmigung, Nachweisbindung, Ablauf).
