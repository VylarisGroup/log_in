# Architektur

## Ausgangslage und Entscheidungen

Das Repository `VylarisGroup/log_in` war beim Start **leer** (keine Commits, keine Branches). Eine Analyse von Altbestand war daher nicht moeglich. Mit dem Auftraggeber vereinbart:

| Entscheidung | Wert |
|---|---|
| Vorgehen | Neuaufbau nach Auftrag |
| Stack | Laravel (wie die uebrigen Vylaris-Tools), PHP 8.3 |
| OIDC-Basis | `league/oauth2-server` 9 + eigene OIDC-Schicht (ID-Token, Discovery, JWKS, UserInfo, Logout) |
| Dash-API | wird von log_in definiert (siehe [API.md](API.md)); Dash implementiert sie |
| Standalone | **kein** Standalone-Betrieb: log_in ist von Dash abhaengig |

## Rollen und Kommunikationsrichtungen

```
Reseller <-> Dash <-> log_in <-> Tools
```

| Richtung | Kanal | Authentifizierung |
|---|---|---|
| Browser -> log_in | OIDC (`/authorize`, `/login`) | Dash prueft Zugangsdaten, SSO-Sitzung in log_in |
| Tool -> log_in | `/token`, `/userinfo`, `/revoke`, `/logout` | Client-Secret (basic/post) + PKCE, Bearer-JWT |
| log_in -> Dash | `/api/vylaris/v1/*` | Ed25519-signierte Anfrage, signierte Antwort |
| Dash -> log_in | `/api/dash/v1/*` | Ed25519-signierte Anfrage, signierte Antwort |
| Dash (als Tool) -> log_in | OIDC wie jedes andere Tool | erste registrierte OIDC-Anwendung |

Es gibt **keine zyklische Abhaengigkeit zur Laufzeit**: die Server-zu-Server-Kanaele benutzen Signaturschluessel, die beim Setup ueber einen Fingerprint-Abgleich etabliert wurden, nie eine Browser-Sitzung oder ein OIDC-Token. Dash kann sich daher ueber log_in anmelden, waehrend log_in Dash ueber einen davon unabhaengigen Kanal befragt.

## Betriebsarten

| | Integriert (einzige Art) |
|---|---|
| Voraussetzung | Dash erreichbar, Fingerprint bestaetigt, Dash importiert den log_in-Schluessel |
| Identitaetsquelle | ausschliesslich Dash (Konto, Mandant, Rollen, Status, MFA) |
| Lokale Daten | nur technische: Clients, Schluessel, SSO-Sitzungen, Tokens, Pairings, Audit |
| Setup-Modus | `uninitialized` -> `awaiting_dash_activation` -> `integrated` |

Ein Modus "Standalone" existiert nicht. Wuerde Dash entfernt, koennen sich keine Benutzer mehr anmelden (fail closed); es werden **nie** zentrale Identitaeten in lokale Konten umgewandelt, weil log_in keine Konten besitzt. Lokale technische Daten bleiben erhalten (Backup/Restore). Ein Moduswechsel ist damit nur "Dash neu anbinden": Wartungszugang oder Recovery-Link -> Dash-URL, Fingerprint, Client neu registrieren (siehe [BOOTSTRAP.md](BOOTSTRAP.md)). Eine Neu-Registrierung ersetzt das Dash-Client-Geheimnis; bestehende Sitzungen und Tokens des alten Dash-Clients werden dadurch ungueltig, weil der alte Client geloescht wird.

## Komponenten

| Komponente | Datei | Aufgabe |
|---|---|---|
| OIDC-Controller | `app/Http/Controllers/Oidc/OidcController.php` | Discovery, JWKS, Authorize, Token, UserInfo, Revoke, Logout |
| Login | `.../Oidc/LoginController.php` | Browser-Anmeldung ueber Dash, SSO-Sitzung |
| Server-Factory | `app/Services/Oidc/ServerFactory.php` | konfiguriert league/oauth2-server (nur Code + Refresh) |
| Grants | `OidcAuthCodeGrant`, `OidcRefreshGrant` | PKCE-Pflicht, Kontopruefung bei Dash, Replay-Schutz |
| ID-Token | `IdTokenResponse`, `ClaimsBuilder` | ID-Token, scope-basierte Claims |
| Schluessel | `KeyManager`, `TokenVerifier` | RS256, Rotation, Widerruf, JWKS |
| Sitzungen | `SsoSessions` | serverseitige SSO-Sitzungen, Widerruf |
| Dash-Client | `app/Services/Dash/DashClient.php` | signierte Aufrufe, Antwortpruefung, Cache |
| Dash-API | `DashApiController`, `VerifyDashSignature` | Verwaltung durch Dash |
| Pairing | `PairingService` | Zustandsautomat, Client-Erzeugung |
| Setup | `SetupService`, `SetupController` | Erstsetup, Wartung, Recovery |
| Updates | `UpdateService` | GitHub-Releases, Pruefsumme, Rollback |

## Datenmodell (technische Daten, keine Konten)

`settings` (Dash-Anbindung, eigene Schluessel; Geheimnisse mit APP_KEY verschluesselt) - `signing_keys` - `oidc_clients` - `sso_sessions` - `oidc_auth_codes` / `oidc_access_tokens` / `oidc_refresh_tokens` - `pairings` - `api_nonces` - `bootstrap_admins` - `recovery_tokens` - `audit_logs` - Laravel `sessions` / `cache`.
Migration: `database/migrations/2026_10_29_000001_create_login_core_tables.php` (versioniert; spaetere Aenderungen kommen als neue Migrationen).

## Sitzungen, Tokens, Rechteentzug

| Objekt | Lebensdauer | Widerruf |
|---|---|---|
| Authorization Code | 60 s, einmalig | bei Wiederverwendung werden Tokens der Sitzung/des Clients widerrufen |
| Access Token (JWT) | 10 min | `jti`-Eintrag, Sitzungs-/Client-/Konto-Status bei jedem UserInfo-Aufruf |
| ID Token | 5 min | nicht widerrufbar (kurzlebig) |
| Refresh Token | 8 h, rotierend, nur mit `offline_access` | Wiederverwendung widerruft die ganze SSO-Sitzung |
| SSO-Sitzung | 60 min Leerlauf, 12 h absolut | Logout, Dash-Push, Kontosperre, Reuse-Erkennung |

Zeitnaher Rechteentzug wird dreifach erreicht: (1) Dash-Push `POST /api/dash/v1/users/{sub}/revoke` (sofort), (2) Refresh und Authorize pruefen den Kontostatus, Refresh **ohne** Cache, (3) Zwischenspeicher der Identitaetsdaten ist auf `DASH_CLAIMS_CACHE_TTL` (Standard 60 s) begrenzt.

## Ausfallverhalten (sicherer Betriebszustand bei Dash-Ausfall)

Abwaegung: **Verfuegbarkeit bereits ausgestellter Sessions vs. Risiko veralteter Berechtigungen.** Entscheidung: *fail closed* fuer alles, was Berechtigungen erzeugt oder erneuert.

| Vorgang bei Dash-Ausfall | Ergebnis |
|---|---|
| Login | abgelehnt, Meldung "Anmeldedienst nicht verfuegbar" |
| `/authorize` (neue Anmeldung bei Tool) | `error=temporarily_unavailable` |
| Code-Austausch, Refresh | HTTP 503 `temporarily_unavailable`, Code bleibt gueltig |
| UserInfo | HTTP 503 (nie Freigabe aus veralteten Daten, ausser innerhalb des Cache-Fensters von max. 60 s) |
| bereits ausgestellte Access/ID-Tokens | gelten bis zu ihrem Ablauf (max. 10 min) bei Tools, die nur die Signatur pruefen |
| Dash-Antwort mit falscher/fehlender Signatur | wie Ausfall, zusaetzlich Protokollfehler im Audit |

Der Preis: Waehrend eines Dash-Ausfalls koennen sich auch gueltige Benutzer nicht neu anmelden. Tools, die ausschliesslich Signatur pruefen, akzeptieren Tokens bis zu 10 Minuten nach einem Rechteentzug; Tools mit hohem Schutzbedarf sollen UserInfo aufrufen.
