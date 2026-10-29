# Vylaris log_in

Zentraler **OpenID-Connect-Provider (SSO)** des Vylaris-Oekosystems. log_in authentifiziert Benutzer fuer die integrierten Tools; die **Identitaeten, Mandanten und Rollen fuehrt ausschliesslich Dash**. log_in speichert keine Benutzerkonten und keine Passwoerter.

```
Reseller <-> Dash <-> log_in <-> integrierte Tools
```

- Reseller sprechen nie direkt mit log_in.
- Tools melden ihre Benutzer ueber log_in an (OIDC Authorization Code Flow mit PKCE).
- Tools werden ausschliesslich ueber das **Vylaris Pairing Protocol** (ueber Dash) angebunden.
- log_in laeuft **nur im integrierten Betrieb** mit Dash. Es gibt keinen Standalone-Modus (Entscheidung des Auftraggebers; das Repository war leer, es gab keinen Altbestand zu erhalten).

## Stack

Laravel 13 / PHP 8.3, [league/oauth2-server](https://oauth2.thephpleague.com/) 9 (gepruefte OAuth2-Kernbibliothek) mit einer eigenen, schmalen OIDC-Schicht, libsodium (Ed25519, X25519) fuer die Dash-Kommunikation, MySQL/MariaDB (SQLite fuer Tests). Keine Daemons, keine Container: Cron + PHP genuegen.

## Schnellstart (Webhosting)

1. Release-Archiv (enthaelt `vendor/`) auf dem Hosting entpacken. Wer das Quell-Archiv nutzt, fuehrt einmal `composer install --no-dev --optimize-autoloader` aus.
2. Domain auf den Ordner `public/` zeigen lassen (Fallback: eine mitgelieferte `.htaccess` im Hauptordner leitet nach `public/` um).
3. `https://<domain>/setup` im Browser oeffnen. Beim ersten Aufruf legt log_in selbst eine lauffaehige `.env` an (`APP_KEY`, Adresse, SQLite, Datei-Sessions, Pseudo-Cron).
4. Setup-Token aus `storage/app/setup-token.txt` (per FTP/Dateimanager) eingeben und den Assistenten durchgehen: **Installation** (Datenbank + Administrator) - **Dash verbinden** (Fingerprint bestaetigen, automatische Registrierung, `dash-bootstrap.json` laden) - **Testen und abschliessen**.

Kein Terminal, kein Cron-Eintrag und keine manuelle `.env`-Bearbeitung noetig. Details: [docs/SETUP.md](docs/SETUP.md), [docs/BOOTSTRAP.md](docs/BOOTSTRAP.md).

## Endpunkte (Kurzuebersicht)

| Zweck | Pfad |
|---|---|
| Discovery | `GET /.well-known/openid-configuration` |
| JWKS | `GET /.well-known/jwks.json` |
| Authorization | `GET /authorize` |
| Token | `POST /token` |
| UserInfo | `GET\|POST /userinfo` |
| Widerruf (RFC 7009) | `POST /revoke` |
| Logout (RP-initiated) | `GET\|POST /logout` |
| Vylaris-Discovery (oeffentlich) | `GET /api/vylaris/v1/discovery`, `GET /.well-known/vylaris-login` |
| Dash-Verwaltungs-API | `/api/vylaris/v1/*` (Bearer-Service-Token + Ed25519-Signatur, nur Dash) |

## Dokumentation

| Datei | Inhalt |
|---|---|
| [DASH_INTEGRATION.md](DASH_INTEGRATION.md) | Briefing fuer die Code-KI, die Dash baut |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architektur, Betriebsarten, Datenmodell, Ausfallverhalten |
| [docs/OIDC.md](docs/OIDC.md) | Unterstuetzte/ausgeschlossene Flows, Claims, Schluessel |
| [docs/API.md](docs/API.md) | Einheitlicher Vylaris-Vertrag v1 (Bearer + Signatur, Fehler, Endpunkte, Token, SSRF) |
| [docs/openapi.yaml](docs/openapi.yaml) | OpenAPI 3.1 |
| [docs/test-vectors.json](docs/test-vectors.json) | Gemeinsame deterministische Signatur-Testvektoren |
| [docs/PAIRING-PROTOCOL.md](docs/PAIRING-PROTOCOL.md) | Pairing-Zustandsautomat und Nachweise |
| [docs/SECURITY.md](docs/SECURITY.md) | Sicherheitsmassnahmen und bekannte Grenzen |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Bedrohungen, Gegenmassnahmen, Tests |
| [docs/BOOTSTRAP.md](docs/BOOTSTRAP.md) | Erstinstallation ohne Authentifizierungsschleife |
| [docs/SETUP.md](docs/SETUP.md) | Installation und Einrichtung |
| [docs/UPDATES.md](docs/UPDATES.md) | Updates, Backups, Wiederherstellung |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Betrieb, Cron, Monitoring, Stoerungen |

## Tests

```bash
php artisan test
```

Letzter dokumentierter Lauf (SQLite in-memory, simuliertes Dash, siehe [docs/SECURITY.md](docs/SECURITY.md#tests)): **103 Tests, 103 bestanden**. Nicht abgedeckte Punkte und Einschraenkungen stehen transparent in [docs/SECURITY.md](docs/SECURITY.md#offene-punkte-und-einschraenkungen).
