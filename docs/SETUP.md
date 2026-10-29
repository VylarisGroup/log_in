# Installation und Einrichtung

## Voraussetzungen

| Komponente | Anforderung |
|---|---|
| PHP | 8.3 mit `sodium`, `openssl`, `mbstring`, `pdo_mysql` (oder `pdo_sqlite`), `zip`, `curl` |
| Datenbank | SQLite (Standard der Web-Installation) oder MySQL 8 / MariaDB 10.6+ |
| Webserver | HTTPS (TLS 1.2+) mit Webroot **nur** auf `public/` |
| Cron | optional: `* * * * * php /pfad/artisan schedule:run >> /dev/null 2>&1` (sonst Pseudo-Cron) |
| Dash | erreichbar per HTTPS und mit der API aus [API.md](API.md), Abschnitt A |

Nicht erforderlich: Docker, Redis, Queue-Worker, Supervisor, Node/npm auf dem Server.

## Installation per Web-Assistent (empfohlen)

1. Release-Archiv von https://github.com/VylarisGroup/log_in/releases laden (enthaelt `vendor/`), `SHA256SUMS` pruefen und im Hosting entpacken. Aus dem Quell-Archiv: einmal `composer install --no-dev --optimize-autoloader` (Hosting-Terminal oder lokal, dann hochladen).
2. Die (Sub-)Domain auf `public/` zeigen lassen. Geht das nicht, genuegt die mitgelieferte `.htaccess` im Hauptordner (leitet nach `public/` um und sperrt `.env`, `storage/`, `vendor/` usw.). HTTPS aktivieren.
3. `https://<domain>/setup` aufrufen. Beim **ersten** Aufruf erzeugt log_in selbst eine `.env` aus `.env.example` mit: neuem `APP_KEY`, `APP_URL`/`OIDC_ISSUER` aus dem aufgerufenen Host, SQLite (`database/database.sqlite`), Datei-Sessions und -Cache sowie `PSEUDO_CRON=true`. Eine vorhandene `.env` wird nicht ueberschrieben (nur ein fehlender `APP_KEY` und die Adresse werden ergaenzt).
4. Das Setup-Token (`storage/app/setup-token.txt`, 32 Zeichen) per FTP/Dateimanager lesen und eingeben. Es wird nie ueber HTTP ausgegeben.
5. **Schritt 1 - Installation:** Umgebungspruefung, Adresse (Issuer; danach nicht mehr aenderbar), Datenbank (SQLite ohne Zugangsdaten oder MySQL/MariaDB mit Verbindungstest) und Setup-Administrator mit TOTP. Ein Klick fuehrt die Migrationen aus, erzeugt die Schluessel und legt den Administrator an. Die DB-Zugangsdaten werden in die `.env` geschrieben.
6. **Schritt 2 - Dash verbinden:** Dash-URL eingeben, Fingerprint mit der Dash-Anzeige vergleichen und eintippen. Danach wird Dash automatisch als OIDC-Anwendung registriert (Standard: `<dash>/auth/callback`, Post-Logout `<dash>/`; Hinweise `oidc_redirect_uris` / `oidc_post_logout_uris` aus der Dash-Discovery haben Vorrang). `dash-bootstrap.json` herunterladen und in Dash importieren ([DASH_INTEGRATION.md](../DASH_INTEGRATION.md)). Das Bundle enthaelt Geheimnisse und wird im Browser nicht angezeigt.
7. **Schritt 3 - Abschluss:** "Pruefen und Setup abschliessen" fuehrt den Verbindungstest (falls noetig) und den Integritaetstest aus. Mit der ersten Dash-Anmeldung endet der Bootstrap ([BOOTSTRAP.md](BOOTSTRAP.md)).

Bis die Datenbank eingerichtet ist, leitet jede Seite auf `/setup`; die API antwortet mit `503 service_unavailable`.

### Cron und Pseudo-Cron

Mit `PSEUDO_CRON=true` (Standard der Web-Installation) werden faellige Aufgaben (Wartung alle 5 Minuten, Backup taeglich) nach Seitenaufrufen ausgefuehrt, hoechstens einmal pro Minute. Das ersetzt keinen echten Cron bei sehr wenig Verkehr: ohne Aufrufe laeuft nichts. Wer Cron hat, setzt `PSEUDO_CRON=false` und traegt `* * * * * php /pfad/artisan schedule:run >> /dev/null 2>&1` ein.

## Installation per Kommandozeile (Alternative)

```bash
cp .env.example .env
php artisan key:generate         # APP_KEY: SICHERN! Ohne ihn sind Schluessel und Backups unlesbar
php artisan migrate --force
php artisan login:setup:init
```

In `.env` anpassen:

| Variable | Bedeutung |
|---|---|
| `APP_URL`, `OIDC_ISSUER` | oeffentliche HTTPS-URL **ohne** Slash am Ende - der Issuer ist Teil aller Tokens und nach Inbetriebnahme nicht mehr zu aendern |
| `APP_ENV=production`, `APP_DEBUG=false` | zwingend |
| `DB_*` | Datenbankverbindung |
| `SESSION_SECURE_COOKIE=true` | Cookies nur ueber HTTPS |
| `PSEUDO_CRON` | `true` fuehrt faellige Aufgaben ohne Cron-Eintrag aus |
| `TRUSTED_PROXIES` | optional, nur wenn ein Reverse-Proxy davor steht (IP/CIDR-Liste oder `*` nur bei vollstaendig kontrolliertem Proxy) |
| `DASH_TIMEOUT`, `DASH_CONNECT_TIMEOUT`, `DASH_CLAIMS_CACHE_TTL` | Dash-Aufrufe (Standard 5 s / 3 s / 60 s) |
| `SERVICE_TOKEN_TTL_DAYS` | Gueltigkeit der Service-Token (Standard 90) |
| `VYLARIS_SSRF_ENFORCE`, `VYLARIS_ALLOW_PRIVATE_TARGETS`, `DASH_ALLOW_HTTP` | SSRF-Lockerungen nur fuer lokale Entwicklung (Standard: strikt). In Produktion wirkungslos |

Dann im Browser `https://<host>/setup` oeffnen (Ablauf wie oben).

## Dateirechte

`storage/`, `bootstrap/cache/`, `database/` (SQLite) und die `.env` (bzw. ihr Ordner) muessen fuer den Webserver-Benutzer beschreibbar sein; `.env` nur fuer diesen Benutzer lesbar (0600/0640). `storage/app/setup-token.txt`, `storage/app/bootstrap/` und `storage/backups/` werden mit 0600/0700 angelegt.

## Pruefung nach der Installation

```bash
php artisan login:status                          # Modus, aktive Schluessel, Dash-Anbindung
curl -s https://<host>/.well-known/openid-configuration
curl -s https://<host>/.well-known/jwks.json
```

Erwartet: Modus `integrated` (nach der ersten Dash-Anmeldung), Issuer entspricht `OIDC_ISSUER`, genau ein aktiver Schluessel in der JWKS.

## Reverse-Proxy-Hinweise

`Authorization`-Header muss unveraendert durchgereicht werden (UserInfo, Token). Header der Dash-API (`X-Vylaris-*`) und der Request-Body duerfen nicht veraendert werden (Signatur). HTTP-Zeitlimit mindestens 15 s.
