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

    'version' => '1.0.0',
];
