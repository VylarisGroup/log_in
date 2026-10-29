# Betrieb

## Zeitplaene (Cron `schedule:run`, jede Minute, oder `PSEUDO_CRON=true`)

Ohne Cron-Eintrag fuehrt `PSEUDO_CRON=true` (Standard der Web-Installation) die faelligen Aufgaben nach Seitenaufrufen aus, hoechstens einmal pro Minute. Bei echtem Cron `PSEUDO_CRON=false` setzen.

| Aufgabe | Takt | Inhalt |
|---|---|---|
| `login:maintenance` | alle 5 Minuten | abgelaufene SSO-Sitzungen entfernen, Schluessel nach Ueberlappung bereinigen, abgelaufene Pairings -> `expired`, unquittierte versiegelte Zugangsdaten loeschen (> 1 h), abgelaufene Setup-Admins deaktivieren, Audit-Eintraege > 180 Tage loeschen |
| `login:backup` | taeglich 03:15 | Sicherung, 14 Staende |

## Befehlsreferenz

| Befehl | Zweck |
|---|---|
| `login:status` | Modus, Schluessel, Dash-Anbindung, Version |
| `login:setup:init` | Setup-Token erzeugen |
| `login:recovery:issue` | einmaliger Wartungslink (15 min) |
| `login:keys:rotate [--revoke=<kid>]` | Rotation bzw. sofortiger Widerruf |
| `login:maintenance` | Aufraeumen von Hand |
| `login:backup`, `login:restore` | Sicherung / Wiederherstellung |
| `login:update:check`, `login:update:apply` | Updates |
| `login:dash:revoke-tokens` | Notfall: alle Service-Token der Dash-Installation widerrufen |

## Schluesselrotation

Empfohlen alle 90 Tage: `php artisan login:keys:rotate`. Neue Tokens tragen sofort die neue `kid`; der alte Schluessel bleibt 7 Tage in der JWKS. Tools muessen die JWKS bei unbekannter `kid` neu laden. Kompromittierung: `--revoke=<kid>`; bestehende Tokens dieses Schluessels werden bei UserInfo abgelehnt.

## Service-Token

Dash rotiert sein Token per `POST /api/vylaris/v1/service-tokens/rotate` (Standardlaufzeit 90 Tage, Empfehlung: nach 60 Tagen). `GET /api/vylaris/v1/health` zeigt `service_token_expires_at`. Ist es abgelaufen oder widerrufen: `php artisan login:recovery:issue` und Bootstrap wiederholen (neues Bundle). Siehe [API.md](API.md) Abschnitt 6.

## Ueberwachung

| Pruefung | Mittel |
|---|---|
| Dienst erreichbar | `GET /.well-known/openid-configuration` (200) |
| Dash-Anbindung | `login:status`; Audit-Eintraege `login.dash_protocol_error`, `api.signature_invalid`, `api.replay_blocked`, `api.forbidden` |
| Cron laeuft | Crontab-Eintrag pruefen (`crontab -l`); `php artisan schedule:list` zeigt die Plaene. Ohne Cron werden Pairings erst beim Zugriff als abgelaufen erkannt und Altdaten nicht bereinigt |
| Fehler | `storage/logs/laravel.log` (taeglich rotiert) |

Das Audit-Log (Tabelle `audit_logs`) enthaelt Zeit, Akteur, Ereignis, Objekt, IP und bereinigte Details. Es werden **nie** Passwoerter, Tokens, Geheimnisse oder Codes protokolliert (`Audit::log` entfernt sensible Schluessel).

## Stoerungen

| Symptom | Ursache / Massnahme |
|---|---|
| Alle Anmeldungen schlagen fehl, "Anmeldedienst nicht verfuegbar" | Dash nicht erreichbar oder Signatur fehlerhaft (fail closed). Dash pruefen, Uhrzeit beider Server (Abweichung < 60 s), `login:status` |
| Dash-Aufrufe geben 401 `timestamp_out_of_range` | NTP auf beiden Servern |
| Tools erhalten `invalid_client` nach Geheimnisrotation | altes Geheimnis laeuft nach 10 min ab; Tool muss das versiegelte neue Geheimnis uebernehmen |
| Tool meldet `invalid_grant` beim Refresh | Refresh-Token wiederverwendet oder Sitzung beendet -> neue Anmeldung |
| Pairing laeuft ab | Fenster (Standard 300 s) in Dash neu oeffnen |
| Dash neu installiert / Schluessel verloren | Recovery-Link, Dash neu anbinden ([BOOTSTRAP.md](BOOTSTRAP.md)) |
| `APP_KEY` verloren | Schluessel und Geheimnisse unlesbar: neu aufsetzen, alle Tools neu pairen |
| Bei Missbrauchsverdacht | betroffene Tools in Dash sperren (`suspend`), Schluessel mit `--revoke`, ggf. Konten in Dash sperren (loest `users/{sub}/revoke` aus) |

## Skalierung und Grenzen

Ein Knoten mit DB-gestuetzten Sitzungen und Cache; mehrere Webknoten sind moeglich, wenn sie dieselbe Datenbank und denselben `APP_KEY` nutzen und der Cache gemeinsam ist (Standard: Datenbank). Rate-Limits laufen ueber den Cache. Lasttests wurden nicht durchgefuehrt.
