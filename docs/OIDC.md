# OpenID Connect

Standards: OpenID Connect Core 1.0 (Authorization Code Flow), OAuth 2.0 (RFC 6749), PKCE (RFC 7636), Token Revocation (RFC 7009), OIDC Discovery 1.0, RP-Initiated Logout 1.0.

## Unterstuetzt

| Merkmal | Wert |
|---|---|
| Response Type | `code` |
| Grants | `authorization_code`, `refresh_token` |
| PKCE | **verpflichtend**, nur `S256` |
| Client-Authentifizierung | `client_secret_basic`, `client_secret_post`, `none` (oeffentliche Clients; per Pairing werden nur vertrauliche Clients erzeugt) |
| Signatur | RS256 (3072 Bit), `kid` im Header |
| Scopes | `openid` (Pflicht), `profile`, `email`, `vylaris`, `offline_access` |
| Antwortmodus | `query` |
| `prompt` | `none`, `login`; ausserdem `max_age` |
| `state`, `nonce` | **verpflichtend** (fehlend -> `invalid_request` per Redirect) |
| Logout | RP-initiated (`/logout`, `id_token_hint`, registrierte `post_logout_redirect_uri`) |
| Widerruf | `/revoke` (RFC 7009) fuer Access- und Refresh-Tokens |

## Bewusst ausgeschlossen

| Ausgeschlossen | Grund |
|---|---|
| Implicit Flow (`token`, `id_token`) | Tokens in URLs, kein PKCE |
| Hybrid Flow | wie oben |
| Resource Owner Password Credentials | Tool wuerde Passwoerter sehen |
| Client Credentials, Device Code | kein Bedarf; kein Maschinen-Zugriff auf Benutzerdaten |
| PKCE `plain` | schwaecher als S256 |
| Request-Objekte (`request`, `request_uri`) | `request_not_supported`; vermeidet SSRF/Parameter-Verwirrung |
| Dynamische Client-Registrierung | Clients entstehen nur ueber das Pairing-Protokoll |
| Endnutzer-Consent-Screen | Clients sind durch den Dash-Administrator im Pairing freigegeben |
| Front-/Back-Channel-Logout | nicht implementiert; stattdessen kurze Token-Lebensdauer und UserInfo-Pruefung |
| Implizite oder Wildcard-Redirect-URIs | nur exakte, registrierte URIs |

## Endpunkte

| Endpunkt | Pfad | Hinweise |
|---|---|---|
| Discovery | `GET /.well-known/openid-configuration` | listet exakt die obigen Faehigkeiten |
| JWKS | `GET /.well-known/jwks.json` | aktiver und (waehrend der Ueberlappung) alter Schluessel, nie private Anteile |
| Authorization | `GET /authorize` | Redirect-URI wird vor jeder Weiterleitung exakt geprueft; bei ungueltigem Client/Redirect **keine** Weiterleitung (HTTP 401) |
| Token | `POST /token` | `Cache-Control: no-store`, Parameter nur im Body |
| UserInfo | `GET\|POST /userinfo` | Bearer; prueft Signatur, Issuer, Ablauf, DB-Status, Sitzung, Client, Konto |
| Revocation | `POST /revoke` | antwortet immer 200 bei gueltiger Client-Authentifizierung |
| End Session | `GET\|POST /logout` | ohne gueltigen `id_token_hint` nie automatische Abmeldung/Weiterleitung (Bestaetigungsseite mit CSRF-Token) |

## Authorization Request

```
GET /authorize?response_type=code&client_id=vl_...&redirect_uri=<exakt registriert>
  &scope=openid%20profile%20email%20vylaris%20offline_access
  &state=<zufaellig>&nonce=<zufaellig>&code_challenge=<S256>&code_challenge_method=S256
```

Fehler nach gueltigem Client/Redirect: Redirect mit `error`, `error_description`, `state`. Scopes ausserhalb der Client-Registrierung -> `invalid_scope` (kein stilles Verkleinern/Erweitern).

## Token Response

```json
{"token_type":"Bearer","expires_in":600,"access_token":"<JWT>","id_token":"<JWT>","refresh_token":"<nur mit offline_access>"}
```

### Access Token (JWT, Header `typ: at+jwt`, `kid`)

`iss`, `aud` (= client_id), `sub`, `jti`, `iat`, `nbf`, `exp`, `client_id`, `scope`, `sid`. Tools sollen die Signatur pruefen, **den Widerrufsstatus aber nur ueber UserInfo erfahren**.

### ID Token (RS256, `kid`)

`iss`, `sub`, `aud`, `azp`, `exp` (5 min), `iat`, `nbf`, `auth_time`, `nonce`, `sid`, `amr`, `at_hash`, plus scope-abhaengig `name` (`profile`), `email`/`email_verified` (`email`), `tenant_id`/`roles` (`vylaris`).
`sid` ist eine oeffentliche Sitzungskennung (Hash), nie die interne Sitzungs-ID.

Pflichtpruefungen im Tool: Signatur ueber JWKS (`kid`), `alg == RS256`, `iss`, `aud` enthaelt die eigene `client_id`, `exp`/`nbf` (max. 60 s Toleranz), `nonce` identisch zur Anfrage, `at_hash`.

## Claims und Scopes (Datensparsamkeit)

| Scope | Claims |
|---|---|
| `openid` | `sub` (Dash-Subject-ID) |
| `profile` | `name` |
| `email` | `email`, `email_verified` |
| `vylaris` | `tenant_id`, `roles` (Liste, Muster `^[a-z0-9][a-z0-9_.:-]{0,63}$`) |
| `offline_access` | Refresh-Token |

Ein Client erhaelt nur die Scopes, die im Pairing freigegeben wurden. `sub` ist die von Dash gelieferte ID und wird gegen die angefragte ID geprueft (Verwechslungsschutz).

## Schluessel und Rotation

- Ein aktiver RS256-Schluessel, privat mit `APP_KEY` verschluesselt in der Datenbank.
- Rotation: `php artisan login:keys:rotate` oder `POST /api/vylaris/v1/keys/rotate`. Der alte Schluessel bleibt 7 Tage (`vylaris.keys.rotation_overlap_days`) in der JWKS, damit laufende Tokens pruefbar bleiben; neue Tokens nutzen sofort den neuen `kid`.
- Kompromittierung: `php artisan login:keys:rotate --revoke=<kid>` bzw. `POST /api/vylaris/v1/keys/{key_id}/revoke` -> Schluessel verschwindet sofort aus der JWKS, damit signierte Tokens werden bei UserInfo abgelehnt; ein neuer aktiver Schluessel entsteht.
- Clients muessen die JWKS zwischenspeichern (Cache-Control 300 s) und bei unbekanntem `kid` neu laden.

## Logout

`GET /logout?id_token_hint=<ID-Token>&post_logout_redirect_uri=<registriert>&state=...` beendet die SSO-Sitzung (`sid`), widerruft deren Tokens und leitet nur zu einer **fuer den Client registrierten** URI weiter. Ohne Hinweis zeigt log_in eine Bestaetigungsseite.
