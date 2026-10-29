# Bedrohungsmodell

## Schutzgueter

Anmeldeergebnis (wer ist wer), Signaturschluessel, Client-Geheimnisse, Dash-Vertrauensanker, Sitzungen und Tokens, Audit-Log.

## Vertrauensgrenzen und Akteure

| Akteur | Vertrauen |
|---|---|
| Dash | autoritativ fuer Identitaeten; nur ueber signierten Kanal |
| Integriertes Tool | vertraut nach Pairing; kann nur eigene Tokens nutzen, keine Verwaltungs-API |
| Reseller | kein Zugriff auf log_in |
| Endbenutzer / Browser | nicht vertraut; Eingaben validiert |
| Serveradmin von log_in | vertraut (hat Dateizugriff, `APP_KEY`) |
| Netzwerkangreifer | kann Verkehr mitlesen/aendern, wenn TLS fehlt; Annahme: TLS vorhanden |

## Bedrohungen und Gegenmassnahmen

| # | Bedrohung | Gegenmassnahme | Test |
|---|---|---|---|
| T1 | Gefaelschte Dash-Anfragen an die Verwaltungs-API | Bearer-Service-Token **und** Ed25519-Signatur, Zeitfenster, Nonce | `DashApiAuthTest`, `MachineContractTest` |
| T2 | Replay einer mitgeschnittenen Dash-Anfrage | Nonce-Tabelle (180 s) + Zeitstempel | `DashApiAuthTest` |
| T3 | Gefaelschte Dash-Antwort (Man-in-the-Middle, "alle Benutzer aktiv") | signierte Antworten, an Anfrage-Nonce gebunden; sonst wie Ausfall | `RevocationAndOutageTest` |
| T4 | Untergeschobener Dash-Schluessel beim Setup | Fingerprint wird ausserhalb des Kanals verglichen und getippt | `SetupBootstrapTest` |
| T5 | Dash-Ausfall wird zur Rechteerweiterung | fail closed; kein Zwischenspeicher ueber 60 s; Refresh immer frisch | `RevocationAndOutageTest` |
| T6 | Entzogene Rechte bleiben wirksam | Push-Widerruf, Konto-/Rollenpruefung bei Authorize/Refresh/UserInfo, kurze Token | `RevocationAndOutageTest` |
| T7 | Autorisierungscode abgefangen | PKCE S256 Pflicht, Code 60 s, einmalig, Reuse widerruft | `OidcFlowTest` |
| T8 | Redirect auf Angreiferseite / Open Redirect | exakte registrierte URIs, keine Weiterleitung bei Fehler, Logout nur mit Hint + registrierter URI | `OidcFlowTest` |
| T9 | CSRF/Login-CSRF, state/nonce-Manipulation | `state` und `nonce` Pflicht, CSRF-Token auf Formularen | `OidcFlowTest` |
| T10 | Gestohlenes Refresh-Token | Rotation, Reuse-Erkennung widerruft die gesamte Sitzung | `OidcFlowTest` |
| T11 | Token-Fälschung / Algorithmus-Verwechslung | nur RS256, festes `kid`-Lookup, Issuer/Aud-Pruefung | `OidcFlowTest`, `KeyRotationTest` |
| T12 | Schluesselkompromittierung | Rotation, Sofort-Widerruf, `APP_KEY`-Verschluesselung | `KeyRotationTest` |
| T13 | Credential Stuffing / Brute Force | Rate-Limits, Fehlversuchszaehler, Dash-Sperrlogik, einheitliche Meldung | `OidcFlowTest` |
| T14 | Benutzerenumeration | gleiche Antwort fuer unbekannt/falsch/gesperrt | `OidcFlowTest` |
| T15 | Boeswilliges Tool im Pairing (Redirect auf fremde Domain, uebergrosse Scopes) | URI-Policy (Host gehoert zur Tool-Domain), Scope-Begrenzung durch Dash-Freigabe, Nachweis bindet URIs und Scopes | `PairingTest` |
| T16 | Pairing ohne Dash-Freigabe oder mit fremden Schluesseln | Zustandsautomat, Dash-Freigabe zuerst, Challenge-Signatur, Einmaligkeit | `PairingTest` |
| T17 | Abfangen des Client-Geheimnisses durch Relay (Dash) oder Log | Sealed Box an Tool-Schluessel, Hash-Speicherung, Loeschung nach Quittung/1 h | `PairingTest` |
| T18 | Uebernahme beim Erstsetup | Token nur per Dateizugriff, befristeter Setup-Admin mit TOTP, Abschluss sperrt Setup, Deaktivierung bei erster Dash-Anmeldung | `SetupBootstrapTest` |
| T19 | Dauerhafter Hintertuer-Zugang | keine Standardkonten; Recovery nur per Shell, 15 min, einmalig | `SetupBootstrapTest` |
| T20 | Manipuliertes Update | SHA-256, Pfadpruefung, Backup, Rollback (Signatur: offen, siehe SECURITY.md) | `UpdateServiceTest` |
| T21 | Verrat von Geheimnissen ueber Logs/Audit | Redaktion sensibler Schluessel, keine Passwoerter im Audit | `OidcFlowTest` |
| T22 | Clickjacking, XSS | CSP, X-Frame-Options, ausgegebene Werte maskiert (Blade) | manuell nicht browser-getestet |
| T23 | Sitzungsfixierung/-diebstahl | Regeneration beim Login, serverseitige Sitzungen, Secure/HttpOnly | `OidcFlowTest` |
| T24 | Verwechslung von Konten (Dash liefert fremde `sub`) | `sub` der Antwort muss der angefragten entsprechen | `RevocationAndOutageTest` |
| T26 | Gestohlenes Service-Token allein | ohne Signaturschluessel wertlos (`invalid_signature`); Token nur als Hash gespeichert, Ablauf, Rotation, Widerruf | `MachineContractTest` |
| T27 | OIDC-/Tool-Token als Maschinen-Token missbraucht | getrennte Token-Kategorien, Hash-Lookup nur in `service_tokens` | `MachineContractTest` |
| T28 | SSRF ueber Dash-URL oder Tool-`base_url` (interne Ziele, DNS-Rebinding, Redirects) | `SsrfGuard`: HTTPS, Adresspruefung, festgenagelte IP, keine Redirects; Lockerung nie in Produktion | `MachineContractTest` |
| T29 | Doppelte Ausfuehrung durch Wiederholung | `Idempotency-Key`, 24 h | `MachineContractTest` |
| T30 | Pairing ohne ausdrueckliche Freigabe oder ausserhalb des Fensters | Fenster Pflicht, `approved_scopes` Pflicht, Nachweis an genehmigte Scopes gebunden | `PairingTest` |
| T25 | DoS | Rate-Limits, Zeitlimits, kleine Antworten; kein Schutz gegen volumetrische Angriffe | nicht getestet |

## Restrisiken

Siehe [SECURITY.md](SECURITY.md#offene-punkte-und-einschraenkungen). Wesentlich: kompromittierter Server oder `APP_KEY`, kompromittiertes Dash (autoritativ, kann beliebige Identitaeten behaupten), Tools mit reiner Signaturpruefung (bis 10 min Verzoegerung), nicht aktive Release-Signatur, volumetrische DoS-Angriffe.
