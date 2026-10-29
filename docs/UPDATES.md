# Updates, Backups, Wiederherstellung

## Versionierung und Quelle

Schema **`JJ.BB.CC[x]`**, Git-Tag **`vJJ.BB.CC[x]`** (z. B. `v26.01.02`, Fehlerkorrektur `v26.01.02a`). Einzige Quelle ist die Datei `VERSION` im Hauptordner (`config('vylaris.version')` liest sie).

| Teil | Bedeutung | Bereich |
|---|---|---|
| `JJ` | Jahreskuerzel (26, 27, ...) | 2 Stellen |
| `BB` | Hauptversion: grosse, neue Funktion | 01-99 |
| `CC` | Nebenversion: kleine Updates | 00-99 |
| `x` | Fehlerkorrektur (Bugfix) als Buchstabe, optional | a-t (20 Stueck) |

Ohne Buchstaben ist es das Release selbst (`26.01.02`), danach folgen `26.01.02a`, `26.01.02b` ... `26.01.02t`. Reihenfolge: `26.01.02` < `26.01.02a` < ... < `26.01.02t` < `26.01.03`. Ueberlauf: nach `t` steigt `CC`, nach `CC` = 99 steigt `BB`. Ein neues Jahr beginnt mit `JJ.01.00`. Eine neue Hauptversion setzt `CC` auf 00, jede neue Haupt- oder Nebenversion hat keinen Buchstaben. Gross-/Kleinschreibung zaehlt (nur Kleinbuchstaben). Reihenfolge und Vergleich: `App\Support\Version`. Tags ausserhalb des Schemas (z. B. alte `1.x`-Tags) werden vom Update ignoriert; eine Installation mit alter Versionsnummer gilt als aelter als jede Version im neuen Schema.

Release: `VERSION` anheben, committen, Tag `v<VERSION>` setzen. Der Workflow `.github/workflows/release.yml` bricht ab, wenn Tag und `VERSION` nicht uebereinstimmen oder das Schema verletzt ist, und baut sonst `log_in-<version>.zip` (inkl. `vendor/`) und `SHA256SUMS`. Updates stammen **ausschliesslich** aus den GitHub-Releases von `VylarisGroup/log_in` (fest im Code, nicht konfigurierbar).

## Befehle

```bash
php artisan login:update:check      # vergleicht mit dem neuesten Release
php artisan login:update:apply      # fuehrt das Update aus
```

## Ablauf von `update:apply`

1. neuestes Release abfragen; nichts tun, wenn aktuell
2. **Backup** (`login:backup`)
3. Archiv laden, **SHA-256 gegen `SHA256SUMS` pruefen**; falls ein Release-Schluessel hinterlegt ist, zusaetzlich die Ed25519-Signatur (`SHA256SUMS.sig`)
4. Archivpfade pruefen (kein `..`, keine absoluten Pfade), entpacken
5. Maintenance-Modus (`down`)
6. Dateien ersetzen; **unberuehrt** bleiben `.env`, `storage/`, `.git`, `database/database.sqlite`. Ersetzte Dateien werden vorher in ein Rollback-Verzeichnis kopiert
7. `migrate --force` (versionierte Migrationen). Schlaegt sie fehl: Dateien werden zurueckgesetzt, Fehler wird gemeldet
8. Caches leeren, Maintenance-Modus aus, Audit-Eintrag `update.applied`

Es gibt keinen automatischen Hintergrund-Update; Updates passieren nur auf Anweisung des Betreibers.

## Backup und Wiederherstellung

```bash
php artisan login:backup [--keep=14]     # storage/backups/login-YYYYMMDD-HHMMSS.json.gz (0600)
php artisan login:restore <datei> [--force]
```

Automatisch taeglich um 03:15 (Cron `schedule:run`). Gesichert werden alle technischen Tabellen (Einstellungen, Schluessel, Clients, Sitzungen, Tokens, Pairings, Setup-/Recovery-Daten, Audit). Geheimnisse und private Schluessel sind **mit `APP_KEY` verschluesselt** im Backup. Folgen:

- `APP_KEY` muss **getrennt vom Backup** gesichert werden; ohne ihn ist die Wiederherstellung wertlos.
- Backups enthalten Sitzungen und Tokens-Hashes; sie wie Zugangsdaten behandeln und verschluesselt ablegen/ausser Haus speichern (Verschluesselung der Ablage ist Sache des Betreibers).
- Nach einer Wiederherstellung auf einen aelteren Stand koennen bereits widerrufene Sitzungen/Tokens wieder gueltig werden. Danach `php artisan login:maintenance` ausfuehren und bei Verdacht Schluessel rotieren (`login:keys:rotate`).

## Datenbank-Rollback

Eine Datenbank-Rueckrolle findet nicht automatisch statt (nur Dateien). Vorgehen bei fehlgeschlagenem Update nach erfolgter Migration: vorheriges Release installieren und `login:restore` mit dem Backup aus Schritt 2.

## Release-Signatur (offen)

`UpdateService::RELEASE_PUBLIC_KEY` ist **leer**; derzeit gilt nur die SHA-256-Pruefung. `SHA256SUMS` stammt aus demselben Release wie das Archiv und schuetzt daher nur vor Uebertragungsfehlern, nicht vor einem kompromittierten GitHub-Konto. Empfehlung: Ed25519-Schluesselpaar erzeugen, privaten Teil als GitHub-Secret hinterlegen, `SHA256SUMS.sig` im Workflow erzeugen, oeffentlichen Teil in die Konstante eintragen (dann wird die Signatur zwingend geprueft). Siehe [SECURITY.md](SECURITY.md#offene-punkte-und-einschraenkungen).
