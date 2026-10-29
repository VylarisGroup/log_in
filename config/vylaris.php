<?php

return [
    // OIDC-Issuer: exakt die oeffentliche HTTPS-Basis-URL von log_in (ohne Slash am Ende).
    'issuer' => rtrim((string) env('OIDC_ISSUER', env('APP_URL', 'http://localhost')), '/'),

    'ttl' => [
        'auth_code' => 60,          // Sekunden
        'access_token' => 600,      // 10 Minuten
        'id_token' => 300,          // 5 Minuten
        'refresh_token' => 28800,   // 8 Stunden, rotierend, einmalig verwendbar
        'sso_idle' => 3600,         // Inaktivitaetsablauf der SSO-Sitzung
        'sso_absolute' => 43200,    // absolute Maximaldauer (12 h)
    ],

    'dash' => [
        'timeout' => (int) env('DASH_TIMEOUT', 5),
        'connect_timeout' => (int) env('DASH_CONNECT_TIMEOUT', 3),
        // Maximale Lebensdauer zwischengespeicherter Identitaetsdaten. Begrenzt die Verzoegerung bei Rechteentzug.
        'claims_cache_ttl' => (int) env('DASH_CLAIMS_CACHE_TTL', 60),
        'clock_skew' => 60,         // erlaubte Zeitabweichung signierter Requests (Sekunden)
        'nonce_ttl' => 180,         // Aufbewahrung der Nonces (> 2 * clock_skew)
        'allow_http' => (bool) env('DASH_ALLOW_HTTP', false), // nur fuer lokale Tests
    ],

    'pairing' => [
        'window' => 300,            // Sekunden, Standard-Pairing-Fenster
        'max_window' => 900,
    ],

    'keys' => [
        'rsa_bits' => 3072,
        'rotation_overlap_days' => 7, // alter Schluessel bleibt so lange in der JWKS
    ],

    'bootstrap' => [
        'admin_ttl_hours' => 72,    // Setup-Admin laeuft spaetestens danach ab
        'recovery_ttl_minutes' => 15,
    ],

    'scopes' => [
        'openid' => 'Anmeldung (Subject-ID)',
        'profile' => 'Name und Anzeigename',
        'email' => 'E-Mail-Adresse',
        'vylaris' => 'Mandant und Rollen im Vylaris-Oekosystem',
        'offline_access' => 'Refresh-Token (Sitzung ueber Access-Token-Lebensdauer hinaus)',
    ],

    // Einheitlicher Vertrag aller Vylaris-Projekte: API-Version und Basis-Pfad (einzige Stelle im Code).
    'api_version' => 'v1',
    'api_prefix' => '/api/vylaris/v1',

    'service_token' => [
        'ttl_days' => (int) env('SERVICE_TOKEN_TTL_DAYS', 90),
        'grace_minutes' => 10,      // Ueberlappung nach Rotation
    ],

    'idempotency_ttl_hours' => 24,

    // SSRF-Schutz fuer die Verbindung zu Dash. Lockerungen wirken nie in Produktion (siehe SsrfGuard).
    'ssrf' => [
        'enforce' => (bool) env('VYLARIS_SSRF_ENFORCE', true),
        'allow_private' => (bool) env('VYLARIS_ALLOW_PRIVATE_TARGETS', false),
    ],

    // Optionaler Pfad der .env (Tests); Standard: base_path('.env').
    'env_path' => env('VYLARIS_ENV_PATH'),
    // Ohne Cron-Eintrag: faellige Aufgaben (Wartung, Backup) werden hoechstens einmal pro Minute nach einer Antwort ausgefuehrt.
    'pseudo_cron' => (bool) env('PSEUDO_CRON', false),
    // Einzige Quelle: Datei VERSION im Hauptordner (Schema JJ.BB.CC[x], siehe App\Support\Version)
    'version' => is_file(base_path('VERSION')) ? trim((string) file_get_contents(base_path('VERSION'))) : '0.0.0',
];
