<?php

namespace App\Services\Vylaris;

use App\Http\Middleware\EnsureInstalled;
use App\Models\Audit;
use App\Models\BootstrapAdmin;
use App\Models\OidcClient;
use App\Models\RecoveryToken;
use App\Models\Setting;
use App\Services\Dash\DashClient;
use App\Services\Oidc\KeyManager;
use App\Services\Oidc\TokenVerifier;
use App\Support\EnvFile;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

/**
 * Begrenzter Erstsetup-Prozess. Kein Standard-Login, keine dauerhaften Bootstrap-Zugangsdaten:
 * Setup-Token (nur per Dateizugriff lesbar) -> Setup-Admin mit TOTP (laeuft ab) -> Schluessel -> Dash-Vertrauen per
 * Fingerprint -> Dash als erste OIDC-Anwendung -> Verbindungstest -> Integritaetstest. Mit dem ersten erfolgreichen
 * OIDC-Login von Dash wird der Setup-Admin deaktiviert und das Bundle geloescht.
 */
class SetupService
{
    public function __construct(private readonly KeyManager $keys, private readonly DashClient $dash) {}

    public function isCompleted(): bool
    {
        return Setting::get('setup.completed') === '1';
    }

    public function mode(): string
    {
        return Setting::get('setup.mode', 'uninitialized');
    }

    public function tokenPath(): string
    {
        return storage_path('app/setup-token.txt');
    }

    public function bundlePath(): string
    {
        return storage_path('app/bootstrap/dash-bootstrap.json');
    }

    /** Erzeugt das Setup-Token (0600) falls noetig. Das Token wird nie ueber HTTP ausgegeben. */
    public function ensureToken(): void
    {
        if ($this->isCompleted() || File::exists($this->tokenPath())) {
            return;
        }
        File::ensureDirectoryExists(dirname($this->tokenPath()));
        File::put($this->tokenPath(), Str::random(32));
        @chmod($this->tokenPath(), 0600);
    }

    public function checkToken(string $given): bool
    {
        if (! File::exists($this->tokenPath())) {
            return false;
        }

        return hash_equals(trim((string) File::get($this->tokenPath())), $given);
    }

    /** @return array<string, array{ok: bool, info: string}> */
    public function environment(): array
    {
        $w = fn (string $p) => is_dir($p) && is_writable($p);

        return [
            'PHP >= 8.3' => ['ok' => PHP_VERSION_ID >= 80300, 'info' => PHP_VERSION],
            'sodium' => ['ok' => extension_loaded('sodium'), 'info' => ''],
            'openssl' => ['ok' => extension_loaded('openssl'), 'info' => ''],
            'mbstring' => ['ok' => extension_loaded('mbstring'), 'info' => ''],
            'storage beschreibbar' => ['ok' => $w(storage_path()), 'info' => storage_path()],
            'HTTPS' => ['ok' => str_starts_with(config('vylaris.issuer'), 'https://') || config('vylaris.dash.allow_http'), 'info' => config('vylaris.issuer')],
            'APP_KEY gesetzt' => ['ok' => (bool) config('app.key'), 'info' => ''],
            '.env beschreibbar' => ['ok' => is_file(EnvFile::path()) ? is_writable(EnvFile::path()) : $w(dirname(EnvFile::path())), 'info' => ''],
            'bootstrap/cache beschreibbar' => ['ok' => $w(base_path('bootstrap/cache')), 'info' => ''],
            'database/ beschreibbar (SQLite)' => ['ok' => $w(database_path()), 'info' => ''],
            'pdo_sqlite oder pdo_mysql' => ['ok' => extension_loaded('pdo_sqlite') || extension_loaded('pdo_mysql'), 'info' => ''],
        ];
    }

    /**
     * Ein-Klick-Installation: Issuer, Datenbank (SQLite oder MySQL), Migrationen, Schluessel und Setup-Admin.
     * Ist die Datenbank bereits eingerichtet, werden nur die fehlenden Teile ergaenzt (wiederholbar).
     *
     * @param  array<string, mixed>  $in
     *
     * @throws \InvalidArgumentException
     */
    public function install(array $in, string $totpSecret): void
    {
        $adminDone = Setting::get('setup.admin_done') === '1';
        if (! $adminDone) {
            if (mb_strlen((string) $in['password']) < 14) {
                throw new \InvalidArgumentException('Das Passwort braucht mindestens 14 Zeichen.');
            }
            if (! Totp::verify($totpSecret, (string) $in['totp_code'])) {
                throw new \InvalidArgumentException('Der TOTP-Code ist ungueltig.');
            }
        }
        $this->applyIssuer($in['issuer'] ?? null);
        if (! EnsureInstalled::installed()) {
            $this->prepareDatabase($in);
        }
        if (! $adminDone) {
            $this->createAdmin((string) $in['username'], (string) $in['password'], $totpSecret, (string) $in['totp_code']);
        }
        $this->generateKeys();
        Audit::log('setup.installed', 'setup');
    }

    private function applyIssuer(?string $issuer): void
    {
        $issuer = rtrim(trim((string) $issuer), '/');
        if ($issuer === '' || $issuer === config('vylaris.issuer')) {
            return;
        }
        if (! filter_var($issuer, FILTER_VALIDATE_URL) || ! preg_match('#^https?://[^/]+$#', $issuer)) {
            throw new \InvalidArgumentException('Die Adresse muss die Form https://host haben (ohne Pfad).');
        }
        if (! str_starts_with($issuer, 'https://') && ! config('vylaris.dash.allow_http')) {
            throw new \InvalidArgumentException('Die Adresse muss HTTPS verwenden.');
        }
        if (Setting::get('login.installation_id') !== null) {
            throw new \InvalidArgumentException('Der Issuer ist Teil aller Tokens und kann nach der Installation nicht mehr geaendert werden.');
        }
        EnvFile::set(['APP_URL' => $issuer, 'OIDC_ISSUER' => $issuer]);
        config(['vylaris.issuer' => $issuer, 'app.url' => $issuer]);
    }

    /** @param  array<string, mixed>  $in */
    private function prepareDatabase(array $in): void
    {
        if (($in['db_mode'] ?? 'sqlite') === 'mysql') {
            foreach (['db_host' => 'Host', 'db_name' => 'Datenbankname', 'db_user' => 'Benutzer'] as $k => $label) {
                if (trim((string) ($in[$k] ?? '')) === '') {
                    throw new \InvalidArgumentException("Datenbank: $label fehlt.");
                }
            }
            $conn = [
                'host' => trim($in['db_host']), 'port' => trim((string) ($in['db_port'] ?? '')) ?: '3306',
                'database' => trim($in['db_name']), 'username' => trim($in['db_user']), 'password' => (string) ($in['db_password'] ?? ''),
            ];
            config(['database.default' => 'mysql'] + collect($conn)->mapWithKeys(fn ($v, $k) => ["database.connections.mysql.$k" => $v])->all());
            DB::purge('mysql');
            try {
                DB::connection('mysql')->getPdo();
            } catch (\Throwable) {
                throw new \InvalidArgumentException('Datenbankverbindung fehlgeschlagen. Host, Name, Benutzer und Passwort pruefen.');
            }
            $env = ['DB_CONNECTION' => 'mysql', 'DB_HOST' => $conn['host'], 'DB_PORT' => $conn['port'], 'DB_DATABASE' => $conn['database'], 'DB_USERNAME' => $conn['username'], 'DB_PASSWORD' => $conn['password']];
        } else {
            $path = (string) (config('database.connections.sqlite.database') ?: database_path('database.sqlite'));
            if ($path !== ':memory:' && ! is_file($path) && @touch($path) === false) {
                throw new \InvalidArgumentException('Die SQLite-Datei konnte nicht angelegt werden (database/ beschreibbar machen).');
            }
            config(['database.default' => 'sqlite']);
            $env = ['DB_CONNECTION' => 'sqlite', 'DB_DATABASE' => $path];
        }
        DB::purge();
        try {
            Artisan::call('migrate', ['--force' => true]);
        } catch (\Throwable $e) {
            report($e);
            throw new \InvalidArgumentException('Die Datenbank konnte nicht eingerichtet werden: '.class_basename($e));
        }
        EnsureInstalled::reset();
        if (! EnsureInstalled::installed()) {
            throw new \InvalidArgumentException('Die Datenbank wurde nicht eingerichtet.');
        }
        EnvFile::set($env);
    }

    /**
     * Standard-Redirect-URIs von Dash (Hinweise aus der Discovery haben Vorrang).
     *
     * @param  array<string, mixed>  $discovered
     * @return array{0: list<string>, 1: list<string>}
     */
    public function defaultDashUris(array $discovered): array
    {
        $base = rtrim((string) $discovered['base_url'], '/');
        $pick = fn (string $k, array $fallback) => is_array($discovered[$k] ?? null) && $discovered[$k] !== [] ? array_values(array_filter($discovered[$k], 'is_string')) : $fallback;

        return [$pick('oidc_redirect_uris', [$base.'/auth/callback']), $pick('oidc_post_logout_uris', [$base.'/'])];
    }

    /** @throws \InvalidArgumentException */
    public function createAdmin(string $username, string $password, string $totpSecret, string $totpCode): BootstrapAdmin
    {
        if (BootstrapAdmin::query()->where('disabled_at', null)->where('expires_at', '>', now())->exists()) {
            throw new \InvalidArgumentException('Es existiert bereits ein aktiver Setup-Administrator.');
        }
        if (! preg_match('/^[A-Za-z0-9_.\-]{3,40}$/', $username)) {
            throw new \InvalidArgumentException('Benutzername: 3-40 Zeichen (A-Z, 0-9, _ . -).');
        }
        if (mb_strlen($password) < 14) {
            throw new \InvalidArgumentException('Das Passwort braucht mindestens 14 Zeichen.');
        }
        if (! Totp::verify($totpSecret, $totpCode)) {
            throw new \InvalidArgumentException('Der TOTP-Code ist ungueltig.');
        }
        $a = BootstrapAdmin::query()->create([
            'username' => $username,
            'password_hash' => Hash::make($password),
            'totp_secret_enc' => Crypt::encryptString($totpSecret),
            'expires_at' => now()->addHours((int) config('vylaris.bootstrap.admin_ttl_hours')),
        ]);
        Setting::put('setup.admin_done', '1');
        Audit::log('setup.admin_created', 'setup', $username);

        return $a;
    }

    public function generateKeys(): void
    {
        $this->keys->ensureActive();
        if (Setting::get('login.installation_id') === null) {
            $kp = Signer::generateKeypair();
            Setting::put('login.installation_id', 'login-'.Str::lower(Str::random(24)));
            Setting::put('login.sign_public', $kp['public']);
            Setting::putSecret('login.sign_secret', $kp['secret']);
        }
        Setting::put('setup.keys_done', '1');
        Audit::log('setup.keys_generated', 'setup');
    }

    /** @return array<string, mixed> Discovery-Daten samt Fingerprint; noch NICHT vertraut. */
    public function discoverDash(string $url): array
    {
        $d = $this->dash->discover($url);
        $d['fingerprint'] = Signer::fingerprint($d['public_key']);
        $d['base_url'] = rtrim($url, '/');

        return $d;
    }

    /** Vertrauen erst nach manueller Bestaetigung des Fingerprints (Out-of-band-Abgleich mit Dash). */
    public function trustDash(string $url, string $typedFingerprint): array
    {
        $d = $this->discoverDash($url);
        $norm = fn (string $s) => strtoupper(preg_replace('/[^A-Fa-f0-9]/', '', $s));
        if (! hash_equals($norm($d['fingerprint']), $norm($typedFingerprint))) {
            throw new \InvalidArgumentException('Der eingegebene Fingerprint stimmt nicht mit dem entdeckten Dash-Schluessel ueberein.');
        }
        Setting::put('dash.base_url', $d['base_url']);
        Setting::put('dash.installation_id', $d['installation_id']);
        Setting::put('dash.public_key', $d['public_key']);
        Setting::put('dash.name', (string) $d['name']);
        isset($d['box_public_key']) ? Setting::put('dash.box_public_key', $d['box_public_key']) : Setting::forget('dash.box_public_key');
        Setting::put('setup.dash_done', '1');
        Setting::forget('setup.test_ok');
        Audit::log('setup.dash_trusted', 'setup', $d['installation_id'], ['fingerprint' => $d['fingerprint']]);

        return $d;
    }

    /**
     * Registriert Dash als erste OIDC-Anwendung und schreibt das einmalige Bundle (0600) fuer die gemeinsame Installation.
     *
     * @param  list<string>  $redirectUris
     * @param  list<string>  $postLogoutUris
     * @return array<string, mixed> Bundle inkl. Klartext-Geheimnis (nur einmal sichtbar)
     */
    public function registerDash(array $redirectUris, array $postLogoutUris): array
    {
        $dashHost = parse_url((string) Setting::get('dash.base_url'), PHP_URL_HOST);
        $errs = array_merge(UriPolicy::validate($redirectUris, (string) $dashHost), UriPolicy::validate($postLogoutUris, (string) $dashHost, false));
        if ($errs !== []) {
            throw new \InvalidArgumentException(implode('; ', $errs));
        }
        $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        $client = DB::transaction(function () use ($redirectUris, $postLogoutUris, $secret) {
            OidcClient::query()->where('is_dash', true)->delete(); // erneute Registrierung ersetzt den alten Dash-Client

            return OidcClient::query()->create([
                'client_id' => 'vl_dash_'.Str::lower(bin2hex(random_bytes(8))),
                'installation_id' => (string) Setting::get('dash.installation_id'),
                'name' => (string) Setting::get('dash.name', 'Dash'),
                'domain' => (string) parse_url((string) Setting::get('dash.base_url'), PHP_URL_HOST),
                'version' => null,
                'confidential' => true,
                'secret_hash' => OidcClient::hashSecret($secret),
                'redirect_uris' => array_values($redirectUris),
                'post_logout_uris' => array_values($postLogoutUris),
                'scopes' => ['openid', 'profile', 'email', 'vylaris', 'offline_access'],
                'status' => 'active',
                'is_dash' => true,
            ]);
        });

        [$inboundToken, $outboundToken] = app(ServiceTokens::class)->bootstrap((string) Setting::get('dash.installation_id'));
        $bundle = [
            'schema' => 'vylaris-login-bootstrap/2',
            'issuer' => config('vylaris.issuer'),
            'discovery_url' => config('vylaris.issuer').'/.well-known/openid-configuration',
            'client_id' => $client->client_id,
            'client_secret' => $secret,
            'token_endpoint_auth_method' => 'client_secret_basic',
            'redirect_uris' => $client->redirect_uris,
            'post_logout_uris' => $client->post_logout_uris,
            'scopes' => $client->scopes,
            'log_in_installation_id' => Setting::get('login.installation_id'),
            'log_in_public_key' => Setting::get('login.sign_public'),
            'log_in_public_key_fingerprint' => Signer::fingerprint((string) Setting::get('login.sign_public')),
            'api_version' => config('vylaris.api_version'),
            'api_base' => config('vylaris.issuer').config('vylaris.api_prefix'),
            'discovery_url_vylaris' => config('vylaris.issuer').'/.well-known/vylaris-login',
            // Service-API-Token (Bearer). Der Betreiber uebergibt das Bundle einmalig; danach nur noch Rotation per API.
            'service_token' => $inboundToken,              // Dash -> log_in
            'login_to_dash_token' => $outboundToken,       // log_in -> Dash (Dash speichert nur den SHA-256-Hash)
            'service_token_scopes' => array_keys(ServiceTokens::SCOPES),
            'service_token_expires_at' => now()->addDays((int) config('vylaris.service_token.ttl_days'))->toIso8601String(),
            'created_at' => now()->toIso8601String(),
        ];
        File::ensureDirectoryExists(dirname($this->bundlePath()));
        File::put($this->bundlePath(), json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        @chmod($this->bundlePath(), 0600);
        Setting::put('setup.client_done', '1');
        Audit::log('setup.dash_client_registered', 'setup', $client->client_id);

        return $bundle;
    }

    /** @return array{ok: bool, message: string} */
    public function testConnection(): array
    {
        try {
            $h = $this->dash->health();
            if (($h['status'] ?? null) !== 'ok') {
                return ['ok' => false, 'message' => 'Dash meldet Status '.($h['status'] ?? 'unbekannt')];
            }
            Setting::put('setup.test_ok', '1');

            return ['ok' => true, 'message' => 'Signierte Verbindung zu Dash funktioniert.'];
        } catch (\Throwable $e) {
            Setting::forget('setup.test_ok');

            return ['ok' => false, 'message' => 'Verbindung fehlgeschlagen: '.class_basename($e).' - '.$e->getMessage()];
        }
    }

    /** @return array<string, array{ok: bool, info: string}> */
    public function integrityChecks(): array
    {
        $r = [];
        $r['Migrationen ausgefuehrt'] = ['ok' => Schema::hasTable('oidc_clients') && Schema::hasTable('pairings'), 'info' => ''];
        $key = $this->keys->active();
        $r['Aktiver Signaturschluessel'] = ['ok' => $key !== null, 'info' => $key?->kid ?? ''];
        $r['JWKS enthaelt aktiven Schluessel'] = ['ok' => $key !== null && collect($this->keys->jwks()['keys'])->contains('kid', $key->kid), 'info' => ''];
        $r['Dash vertraut (Fingerprint bestaetigt)'] = ['ok' => Setting::get('setup.dash_done') === '1', 'info' => ''];
        $r['Dash als OIDC-Client registriert'] = ['ok' => OidcClient::query()->where('is_dash', true)->where('status', 'active')->exists(), 'info' => ''];
        $r['Dash-API-Verbindung getestet'] = ['ok' => Setting::get('setup.test_ok') === '1', 'info' => ''];

        // Funktionstest der Token-Kette: ein ID-aehnliches JWT signieren und mit dem Verifier pruefen.
        $ok = false;
        if ($key !== null) {
            $cfg = Configuration::forAsymmetricSigner(new Sha256, InMemory::plainText($this->keys->privatePem($key)), InMemory::plainText('empty', 'empty'));
            $jwt = $cfg->builder()->issuedBy(config('vylaris.issuer'))->withHeader('kid', $key->kid)->issuedAt(new \DateTimeImmutable)->expiresAt(new \DateTimeImmutable('+60 seconds'))->getToken($cfg->signer(), $cfg->signingKey())->toString();
            $ok = app(TokenVerifier::class)->verify($jwt) !== null;
        }
        $r['Token-Signatur-Selbsttest'] = ['ok' => $ok, 'info' => ''];

        return $r;
    }

    /** @return bool true wenn alle Pruefungen bestanden und das Setup abgeschlossen wurde */
    public function finish(): bool
    {
        if (Setting::get('setup.test_ok') !== '1' && Setting::get('setup.client_done') === '1') {
            $this->testConnection();
        }
        foreach ($this->integrityChecks() as $c) {
            if (! $c['ok']) {
                return false;
            }
        }
        Setting::put('setup.completed', '1');
        Setting::put('setup.mode', 'awaiting_dash_activation');
        File::delete($this->tokenPath());
        Audit::log('setup.completed', 'setup');

        return true;
    }

    /** Wird nach dem ersten erfolgreichen OIDC-Token fuer den Dash-Client aufgerufen: Bootstrap endet. */
    public function activateFromDash(): void
    {
        if ($this->mode() !== 'awaiting_dash_activation') {
            return;
        }
        BootstrapAdmin::query()->whereNull('disabled_at')->update(['disabled_at' => now(), 'disabled_reason' => 'dash_activated']);
        File::delete($this->bundlePath());
        Setting::put('setup.mode', 'integrated');
        Audit::log('setup.dash_activated', 'dash');
    }

    public function issueRecoveryToken(): string
    {
        $token = Str::random(48);
        RecoveryToken::query()->create(['token_hash' => hash('sha256', $token), 'expires_at' => now()->addMinutes((int) config('vylaris.bootstrap.recovery_ttl_minutes'))]);
        Audit::log('recovery.issued', 'cli');

        return $token;
    }

    public function consumeRecoveryToken(string $token): bool
    {
        return DB::transaction(function () use ($token) {
            $t = RecoveryToken::query()->where('token_hash', hash('sha256', $token))->lockForUpdate()->first();
            if ($t === null || $t->used_at !== null || $t->expires_at->isPast()) {
                return false;
            }
            $t->update(['used_at' => now()]);
            Audit::log('recovery.used', 'web');

            return true;
        });
    }
}
