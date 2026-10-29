# Installation und Einrichtung

## Voraussetzungen

| Komponente | Anforderung |
|---|---|
| PHP | 8.3 mit `sodium`, `openssl`, `mbstring`, `pdo_mysql` (oder `pdo_sqlite`), `zip`, `curl` |
| Datenbank | MySQL 8 / MariaDB 10.6+ (SQLite nur fuer Tests/Kleinstbetrieb) |
| Webserver | HTTPS (TLS 1.2+) mit Webroot **nur** auf `public/` |
| Cron | `* * * * * php /pfad/artisan schedule:run >> /dev/null 2>&1` |
| Dash | erreichbar per HTTPS und mit der API aus [API.md](API.md), Abschnitt A |

Nicht erforderlich: Docker, Redis, Queue-Worker, Supervisor, Node/npm auf dem Server.

## Installation

```bash
# Release-Archiv von https://github.com/VylarisGroup/log_in/releases laden (enthaelt vendor/), SHA256SUMS pruefen, entpacken
cp .env.example .env
```

In `.env` anpassen:

| Variable | Bedeutung |
|---|---|
| `APP_URL`, `OIDC_ISSUER` | oeffentliche HTTPS-URL **ohne** Slash am Ende - der Issuer ist Teil aller Tokens und nach Inbetriebnahme nicht mehr zu aendern |
| `APP_ENV=production`, `APP_DEBUG=false` | zwingend |
| `DB_*` | Datenbankverbindung |
| `SESSION_SECURE_COOKIE=true` | Cookies nur ueber HTTPS |
| `TRUSTED_PROXIES` | optional, nur wenn ein Reverse-Proxy davor steht (IP/CIDR-Liste oder `*` nur bei vollstaendig kontrolliertem Proxy) |
| `DASH_TIMEOUT`, `DASH_CONNECT_TIMEOUT`, `DASH_CLAIMS_CACHE_TTL` | Dash-Aufrufe (Standard 5 s / 3 s / 60 s) |
| `SERVICE_TOKEN_TTL_DAYS` | Gueltigkeit der Service-Token (Standard 90) |
| `VYLARIS_SSRF_ENFORCE`, `VYLARIS_ALLOW_PRIVATE_TARGETS`, `DASH_ALLOW_HTTP` | SSRF-Lockerungen nur fuer lokale Entwicklung (Standard: strikt). In Produktion wirkungslos |

```bash
php artisan key:generate         # APP_KEY: SICHERN! Ohne ihn sind Schluessel und Backups unlesbar
php artisan migrate --force
php artisan login:setup:init
```

Dann im Browser `https://<host>/setup` oeffnen und den Assistenten durchlaufen (Ablauf: [BOOTSTRAP.md](BOOTSTRAP.md)). Anschliessend uebergibt der Betreiber das Bundle an Dash ([DASH_INTEGRATION.md](../DASH_INTEGRATION.md)).

## Dateirechte

`storage/` und `bootstrap/cache/` muessen fuer den Webserver-Benutzer beschreibbar sein; `.env` nur fuer diesen Benutzer lesbar (0600/0640). `storage/app/setup-token.txt`, `storage/app/bootstrap/` und `storage/backups/` werden mit 0600/0700 angelegt.

## Pruefung nach der Installation

```bash
php artisan login:status                          # Modus, aktive Schluessel, Dash-Anbindung
curl -s https://<host>/.well-known/openid-configuration
curl -s https://<host>/.well-known/jwks.json
```

Erwartet: Modus `integrated` (nach der ersten Dash-Anmeldung), Issuer entspricht `OIDC_ISSUER`, genau ein aktiver Schluessel in der JWKS.

## Reverse-Proxy-Hinweise

`Authorization`-Header muss unveraendert durchgereicht werden (UserInfo, Token). Header der Dash-API (`X-Vylaris-*`) und der Request-Body duerfen nicht veraendert werden (Signatur). HTTP-Zeitlimit mindestens 15 s.
