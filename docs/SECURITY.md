# Sicherheit

## Grundsaetze

- **Dash ist autoritativ**, log_in speichert keine Konten und keine Passwoerter. Zugangsdaten werden nur durchgereicht und nicht protokolliert.
- **Fail closed**: bei Dash-Ausfall oder fehlerhafter Dash-Signatur werden keine neuen Berechtigungen erzeugt oder erneuert.
- **Minimale Faehigkeiten**: nur Authorization Code + Refresh, PKCE S256 Pflicht, exakte Redirect-URIs, keine dynamische Registrierung ([OIDC.md](OIDC.md)).
- **Zwei Faktoren fuer jeden Maschinenrequest**: Bearer-Service-Token (Installation, Scopes, Ablauf, Widerruf) *und* Ed25519-Signatur; keines allein genuegt.
- **Keine manuell kopierten Zugangsdaten**: Clients entstehen nur ueber das Pairing, Geheimnisse werden mit X25519-Sealed-Box ausgeliefert.

## Massnahmen

| Bereich | Massnahme |
|---|---|
| Server-zu-Server | Bearer-Service-Token (nur Hash gespeichert, Scopes, Ablauf 90 Tage, Rotation als Sealed Box, Widerruf) + Ed25519-Signatur ueber Methode, Pfad, Zeitstempel, Nonce, Body-Hash; signierte Antworten inkl. `X-Vylaris-Key-Id`, gebunden an die Anfrage-Nonce; Toleranz 60 s; Nonce-Tabelle gegen Replay (atomar per Unique-Key); Idempotency-Key (24 h); Zeitlimits 5 s / 3 s; einheitlicher Fehlervertrag ohne interne Details |
| SSRF | Aufrufe an Dash: nur HTTPS, keine privaten/Loopback/Link-Local/CGNAT/Multicast-Ziele, DNS-Aufloesung geprueft und festgenagelt, Redirects aus; `base_url` von Tools wird bei Pairing validiert; Lockerungen wirken nie in Produktion |
| Pairing | explizit geoeffnetes Fenster (30-900 s), ausdrueckliche Genehmigung einer Scope-Teilmenge, sprachneutraler Nachweis, Sealed Box fuer Geheimnisse |
| Vertrauensbasis | Dash-Schluessel erst nach manueller Fingerprint-Bestaetigung; Dash-API-Eingaben werden strikt validiert (Status, Rollenmuster, `sub`-Identitaet) |
| Tokens | RS256 (3072 Bit), `kid`, Rotation mit 7 Tagen Ueberlappung, sofortiger Widerruf; Codes 60 s und einmalig, Access 10 min, ID 5 min, Refresh 8 h rotierend; Wiederverwendung von Code oder Refresh-Token widerruft die Sitzung/Tokens |
| Geheimnisse | Client-Geheimnisse nur als Hash (`hash_equals`), 10 min Uebergang bei Rotation; Signaturschluessel und Setup-Geheimnisse mit `APP_KEY` verschluesselt (AES-256) |
| Sitzungen | serverseitig, Leerlauf 60 min, absolut 12 h, `sid` als Hash; Cookies `Secure`, `HttpOnly`, `SameSite`; Sitzungs-ID wird beim Login regeneriert |
| Browser | CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, HSTS; CSRF fuer Formulare; `Cache-Control: no-store` bei Token/UserInfo/API |
| Missbrauch | Rate-Limits: `/login` 30/min plus 8 Fehlversuche je Konto/IP-Schluessel, `/authorize` 60/min, `/token` 120/min, `/userinfo` 240/min, `/revoke` 60/min, `/setup` 60/min, Dash-API 300/min; zusaetzlich Drosselung bei Dash |
| Fehlermeldungen | einheitliche Meldung bei falschem Passwort/gesperrtem/unbekanntem Konto; keine Details zu Signatur- oder Schluesselfehlern gegenueber Browsern |
| Redirects | exakte Uebereinstimmung; Redirect-/Logout-URIs ohne Wildcards, ohne Fragment, HTTPS, Host passend zur Domain des Tools; bei ungueltigem Client/Redirect keine Weiterleitung |
| Logout | Weiterleitung nur auf registrierte URI und nur mit gueltigem `id_token_hint`; sonst Bestaetigungsseite mit CSRF |
| Audit | Anmeldungen, Fehlschlaege, Token-/Client-/Schluesselereignisse, Pairing, Setup, Recovery, Updates; Retention 180 Tage; sensible Felder werden entfernt |
| Updates | ausschliesslich GitHub-Releases des festen Repositories, SHA-256-Pruefung, Backup und Rollback der Dateien |

## Tests

Letzter Lauf (`php artisan test`, SQLite in-memory, simuliertes Dash): **116 Tests, 116 bestanden, 831 Assertions**.

| Datei | Tests | Schwerpunkt |
|---|---|---|
| `OidcFlowTest` | 27 | Discovery, JWKS, PKCE-Pflicht, state/nonce, Redirect-Pruefung, Code-Replay, Refresh-Rotation und Reuse, UserInfo, Revoke, Logout, Scope-Begrenzung, MFA-Login |
| `MachineContractTest` | 14 | Bearer Pflicht, Signatur allein reicht nicht, OIDC-Token als Bearer abgelehnt, Token nur als Hash, abgelaufen/widerrufen/Installation widerrufen, fehlender Scope (signierte 403), Fehlerformat, Alt-Pfade 404, Discovery unsigniert, Idempotenz, Token-Rotation (Sealed Box), ausgehende Bearer-Aufrufe, SSRF-Schutz |
| `DashApiAuthTest` | 8 | Signatur, Zeitstempel, Replay, falscher Schluessel/Key-Id, manipulierter Body, unsignierte/gefaelschte Dash-Antworten, HTTPS-Pflicht |
| `RevocationAndOutageTest` | 9 | fail closed, Dash-Ausfall, Kontosperre, Push-Widerruf, Cache-Grenzen |
| `PairingTest` | 18 | Zustandsautomat, offenes Fenster, ausdrueckliche Genehmigung, Nachweisbindung, URI-/base_url-Policy, Konflikte, Ablauf, Versiegelung, Rotation, Trennen |
| `KeyRotationTest` | 5 | Rotation, Ueberlappung, Widerruf, JWKS |
| `SetupBootstrapTest` | 11 | Token, Admin/TOTP, Fingerprint, Bundle inkl. Service-Token, Aktivierung, Recovery, Sperre nach Abschluss |
| `InstallerTest` | 12 | `.env`-Provisionierung, Web-Installation (Admin, Schluessel, Issuer), Ablehnung schwacher Eingaben, automatische Dash-Registrierung, Bundle-Download, Abschluss mit Verbindungstest, tolerante Discovery, Setup-Weiterleitung ohne Datenbank, Pseudo-Cron |
| `UpdateServiceTest` | 4 | Pruefsummen, Release-Abgleich |
| `CryptoAndPolicyTest` | 6 | Signer, TOTP, UriPolicy |
| `SignatureVectorsTest` | 2 | gemeinsame deterministische Vektoren (`docs/test-vectors.json`: Request, Response, Pairing-Nachweis) |

Die Tests laufen gegen **FakeDash** (`tests/Support/FakeDash.php`), nicht gegen ein echtes Dash oder den Reseller.

## Offene Punkte und Einschraenkungen

Ehrliche Liste dessen, was fehlt, nicht getestet wurde oder bewusst begrenzt ist:

1. **Kein Test gegen ein echtes Dash oder den Reseller.** Es gibt nur Contract-Tests mit gemeinsamen Vektoren. Zwei von log_in festgelegte Dash-Schnittstellen sind in der gemeinsamen Masterspezifikation nicht beschrieben und muessen mit der Dash-Implementierung abgeglichen werden: `POST /auth/credentials/verify` (Zugangsdatenpruefung) und das Schema von `GET /users/{id}` ([API.md](API.md) Abschnitt 5). Ebenso das Schema von `/.well-known/vylaris-dash` (inkl. `box_public_key` fuer die Token-Rotation). Bis zur Integration ist der End-to-End-Betrieb nicht nachgewiesen.
2. **Nicht ausgefuehrt:** Lasttests, Penetrationstest/externes Audit, Tests mit MySQL/MariaDB (Tests laufen nur mit SQLite), Tests auf einem realen Webserver mit Reverse-Proxy, Test des echten GitHub-Update-Pfads (Download/Entpacken/Migration/Rollback wurde nur in Teilen - Pruefsumme, Release-Abgleich - automatisiert getestet), manuelle Browser-Tests der Oberflaeche und Barrierefreiheit.
3. **Release-Signatur nicht aktiv** (`RELEASE_PUBLIC_KEY` leer): ein kompromittiertes GitHub-Konto koennte ein manipuliertes Release samt passender `SHA256SUMS` ausliefern. Siehe [UPDATES.md](UPDATES.md).
4. **Update ersetzt nur Dateien, loescht keine entfallenen.** Alte Dateien frueherer Versionen bleiben liegen. Datenbank-Rollback ist manuell (Backup).
5. **Kein Front-/Back-Channel-Logout.** Tools erfahren einen Rechteentzug nur ueber UserInfo/Refresh oder nach Ablauf der Tokens (max. 10 min Access-Token).
6. **Signaturpruefung in Tools** ohne UserInfo erkennt keinen Widerruf vor Ablauf (siehe [OIDC.md](OIDC.md)).
7. **Setup-Token liegt im Klartext auf dem Dateisystem** (0600), bis das Setup abgeschlossen ist. Wer Dateizugriff hat, kann das Setup uebernehmen ([BOOTSTRAP.md](BOOTSTRAP.md)).
8. **Bootstrap-Bundle** liegt bis zur ersten Dash-Anmeldung im Klartext (0600) auf dem Server; der Transport zu Dash ist Aufgabe des Betreibers.
9. **Backups** enthalten verschluesselte Schluessel; Schutz der Backup-Dateien und des `APP_KEY` liegt beim Betreiber. Kein Backup-Offsite-Transfer integriert.
10. **MFA:** log_in setzt kein eigenes MFA fuer Benutzer ein; MFA und Sperrlogik liegen vollstaendig bei Dash. Nur der Setup-Admin nutzt TOTP.
11. **Kein DPoP/mTLS** fuer Token-Bindung; Bearer-Tokens sind uebertragbar bis zum Ablauf.
12. **Ein einziger aktiver Signaturalgorithmus (RS256).** Kein ES256/EdDSA.
13. **Rate-Limits liegen im Cache** (Standard: Datenbank). Hinter Proxy muss `TRUSTED_PROXIES` korrekt gesetzt sein, sonst gilt die Proxy-IP als Client-IP.
14. **Mehrknotenbetrieb** nicht getestet.
15. **Sprache:** Oberflaeche und Dokumentation nur auf Deutsch.
16. **Rotation der Ed25519-Signaturschluessel zwischen Dash und log_in** ist nicht als eigener Online-Vorgang implementiert (nur Token-Rotation und OIDC-Schluesselrotation). Ein Tausch erfolgt ueber Recovery-Link und erneuten Bootstrap.
17. **Service-Token laufen nach 90 Tagen ab.** Rotiert Dash nicht rechtzeitig, ist die Verwaltungs-API gesperrt, bis ein Recovery-Link den Bootstrap wiederholt.
18. **SSRF/DNS:** Das Festnageln der Zieladresse gilt fuer die Verbindung zu Dash; die `base_url` von Tools wird nur formal und auf private IP-Literale geprueft (log_in verbindet sich nie zu Tools, Hostnamen werden nicht aufgeloest).
19. **OpenAPI-Datei** wurde syntaktisch (YAML) geprueft, aber nicht mit einem OpenAPI-Validator oder Codegenerator getestet.
20. **Web-Installer nicht auf echtem Hosting getestet:** SQLite- und MySQL-Einrichtung (inkl. Migration ueber den Browser) sowie das Schreiben der `.env` sind nur mit simulierter Datenbank bzw. Hilfsfunktionen getestet; der MySQL-Pfad wurde nie gegen einen echten Server ausgefuehrt.
21. **Erster `/setup`-Aufruf ist offen:** Wer die Adresse vor dem Betreiber aufruft, loest die `.env`-Erzeugung aus, braucht fuer jeden weiteren Schritt aber das Setup-Token (nur per Dateizugriff lesbar). Die URL deshalb unmittelbar nach dem Entpacken aufrufen und das Setup abschliessen. Die erzeugte `.env` leitet die Adresse aus dem `Host`-Header ab und ist im Assistenten korrigierbar, bevor Schluessel entstehen.
22. **Pseudo-Cron** laeuft nur bei Seitenaufrufen und nach der Antwort im selben PHP-Prozess; bei sehr wenig Verkehr verzoegern sich Wartung und Backup.
23. **Dash-Discovery:** log_in akzeptiert Schluessel aus `public_key` oder `keys[]` und leitet die API-Version aus `api_base` ab, verlangt aber weiterhin die einheitliche API v1 (`/api/vylaris/v1`, Bearer-Service-Token, Signaturen). Ein Dash mit dem alten Protokoll kann nicht angebunden werden.
24. **Back-Channel-Logout** (von Dash angeboten) ist in log_in nicht umgesetzt.
