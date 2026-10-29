# Bootstrap ohne Authentifizierungsschleife

## Das Problem

Dash will sich ueber log_in anmelden, log_in vertraut nur Dash. Ohne Zusatzmassnahmen gaebe es entweder einen dauerhaften Hintertuer-Zugang oder eine Henne-Ei-Schleife.

## Loesung

1. **Server-zu-Server-Vertrauen ist unabhaengig von OIDC.** log_in und Dash vertrauen einander ueber je einen Ed25519-Schluessel, der **einmalig per Fingerprint-Abgleich** bestaetigt wird (kein Browser-Login, kein Token). Damit kann log_in Dash befragen, bevor irgendein Benutzer angemeldet ist.
2. **Das Erstsetup ist ein eng begrenzter Prozess** mit einem befristeten Setup-Admin, der **nie** als regulaerer Zugang dient und nach der ersten erfolgreichen Dash-Anmeldung abgeschaltet wird.

## Ablauf

| # | Schritt | Zugriff / Schutz |
|---|---|---|
| 0 | `php artisan login:setup:init` | erzeugt `storage/app/setup-token.txt` (Modus 0600, 32 Zeichen). Das Token wird **nie** ueber HTTP ausgegeben; wer es lesen kann, hat Dateizugriff auf den Server |
| 1 | `/setup` -> Token eingeben | Rate-Limit 60/min, Vergleich zeitkonstant, Sitzung wird danach regeneriert |
| 2 | Pruefung der Umgebung | PHP >= 8.3, sodium, openssl, mbstring, `storage` beschreibbar, HTTPS (Issuer), `APP_KEY` gesetzt. `APP_DEBUG`/Cron werden **nicht** automatisch geprueft (siehe [SETUP.md](SETUP.md)) |
| 3 | Setup-Admin anlegen | Mindestens 14 Zeichen Passwort (Argon2/bcrypt-Hash), **TOTP-Pflicht** (Geheimnis wird angezeigt, Code muss bestaetigt werden), **laeuft nach 72 h ab** (`bootstrap.admin_ttl_hours`) |
| 4 | Schluessel erzeugen | RS256-Signaturschluessel (OIDC) + Ed25519-Schluessel (Dash-Kanal), privat mit `APP_KEY` verschluesselt |
| 5 | Dash entdecken | `GET <dash>/api/vylaris/v1/discovery`; angezeigt wird der **Fingerprint** des Dash-Schluessels. **Noch kein Vertrauen** |
| 6 | Fingerprint bestaetigen | Der Administrator vergleicht den Fingerprint ausserhalb des Kanals (Dash-Oberflaeche) und **tippt** ihn ein; erst bei Uebereinstimmung wird der Schluessel gespeichert |
| 7 | Dash als erste OIDC-Anwendung registrieren | Redirect-URIs muessen zum Dash-Host passen (UriPolicy). Es entsteht `vl_dash_<hex>` mit zufaelligem 256-Bit-Geheimnis |
| 8 | Bundle | `storage/app/bootstrap/dash-bootstrap.json` (0600), Schema `vylaris-login-bootstrap/1` - Inhalt siehe [DASH_INTEGRATION.md](../DASH_INTEGRATION.md). Das Geheimnis wird dem Administrator **nicht** im Browser angezeigt |
| 9 | Verbindungstest | signierte Aufrufe `GET /log-in/health` mit Pruefung der signierten Antwort; scheitert er, kann nicht abgeschlossen werden |
| 10 | Integritaetstest | Migrationen vorhanden, aktiver Signaturschluessel, JWKS enthaelt ihn, Dash vertraut, Dash-Client aktiv, Verbindungstest bestanden, Token-Selbsttest (JWT signieren und verifizieren). Nur wenn alles besteht, schliesst `finish` das Setup ab |
| 11 | Abschluss | `setup.mode = awaiting_dash_activation`; weitere Setup-Schritte sind gesperrt |
| 12 | **Erste Dash-OIDC-Anmeldung** | Beim ersten erfolgreichen Code-Austausch des Dash-Clients ruft log_in `activateFromDash()` auf: `setup.mode = integrated`, Setup-Admin deaktiviert, Bundle-Datei **geloescht**, Setup-Token geloescht |

Nach Schritt 12 gibt es **keinen** privilegierten Zugang mehr. Es existieren keine Standard-Passwoerter, keine dauerhaften Admin-Konten und keine festen Tokens.

## Dash-Seite des Bootstraps

Dash liest das Bundle (gemeinsamer Dateizugriff oder sicherer Transport durch den Betreiber, der beide Server verwaltet), importiert `log_in_public_key` nach Abgleich des Fingerprints (`log_in_public_key_fingerprint`), traegt Client-ID und Geheimnis als OIDC-Client ein und meldet seine Administratoren ab sofort ueber log_in an. Keine der beiden Seiten braucht dafuer einen bereits laufenden Login der anderen.

## Wartung und Recovery (nach Abschluss)

| Situation | Weg |
|---|---|
| Schluessel rotieren | `php artisan login:keys:rotate` oder Dash-API |
| Dash neu anbinden / Dash-Schluessel erneuern | Recovery-Link: `php artisan login:recovery:issue` gibt eine einmalige URL aus (15 min gueltig, Hash gespeichert, einmal verwendbar). Sie fuehrt in den eng begrenzten Wartungsmodus des Setups (Schritte 5-11). Voraussetzung: Shell-Zugriff auf den Server |
| Setup-Admin | wird nicht neu aktiviert; Recovery-Link ersetzt ihn |
| Dash dauerhaft unerreichbar | Anmeldung bleibt gesperrt (fail closed); keine Hintertuer. Behebung: Dash reparieren oder neu anbinden |

Alle Schritte werden im Audit-Log festgehalten (`setup.*`, `recovery.*`), ohne Geheimnisse.

## Gewollte Einschraenkungen

- Wer Dateizugriff auf den Server hat, kann ein Setup-Token lesen und das Setup *vor* Abschluss uebernehmen. Das ist die Vertrauensbasis (Betreiber = Serveradmin). Daher: Setup unmittelbar nach `login:setup:init` durchfuehren, Webroot nur auf `public/`.
- Das Setup-Fenster schliesst nicht von selbst, solange `setup.completed` fehlt; der Setup-Admin laeuft nach 72 h ab, das Token bleibt bis zum Abschluss. Wird das Setup nicht beendet, `storage/app/setup-token.txt` loeschen.
