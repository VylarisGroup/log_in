<?php

use App\Models\Setting;
use App\Services\Oidc\KeyManager;
use App\Services\Oidc\SsoSessions;
use App\Services\Vylaris\ServiceTokens;
use App\Services\Vylaris\SetupService;
use App\Services\Vylaris\UpdateService;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schedule;

Artisan::command('login:setup:init', function (SetupService $setup) {
    $setup->ensureToken();
    $this->info('Setup-Token liegt (0600) in: '.$setup->tokenPath());
    $this->line('Oeffne '.config('vylaris.issuer').'/setup und gib den Inhalt der Datei ein.');
})->purpose('Erzeugt das Setup-Token fuer den Erstsetup-Assistenten');

Artisan::command('login:keys:rotate {--revoke= : kid eines kompromittierten Schluessels sofort widerrufen}', function (KeyManager $keys) {
    if ($kid = $this->option('revoke')) {
        $keys->revoke($kid, 'cli');
        $this->warn("Schluessel $kid widerrufen; neuer aktiver Schluessel erzeugt. Alle damit signierten Tokens sind ungueltig.");

        return;
    }
    $k = $keys->rotate('cli');
    $this->info('Neuer aktiver Schluessel: '.$k->kid.' (alter bleibt '.config('vylaris.keys.rotation_overlap_days').' Tage in der JWKS)');
})->purpose('Rotiert den Token-Signaturschluessel oder widerruft einen kompromittierten');

Artisan::command('login:recovery:issue', function (SetupService $setup) {
    $t = $setup->issueRecoveryToken();
    $this->warn('Einmal-Link, gueltig '.config('vylaris.bootstrap.recovery_ttl_minutes').' Minuten, einmal verwendbar:');
    $this->line(config('vylaris.issuer').'/setup/recover/'.$t);
})->purpose('Stellt einen Einmal-Wiederherstellungslink aus (nur mit Server-Zugriff)');

Artisan::command('login:maintenance', function (KeyManager $keys, SsoSessions $sessions) {
    $sessions->purgeExpired();
    $keys->prune();
    DB::table('pairings')->whereIn('state', ['requested', 'dash_approved'])->where('expires_at', '<', now())->update(['state' => 'expired', 'sealed_credentials' => null]);
    DB::table('pairings')->where('state', 'active')->whereNull('credentials_acked_at')->where('confirmed_at', '<', now()->subHour())->update(['sealed_credentials' => null]);
    DB::table('bootstrap_admins')->whereNull('disabled_at')->where('expires_at', '<', now())->update(['disabled_at' => now(), 'disabled_reason' => 'expired']);
    DB::table('audit_logs')->where('created_at', '<', now()->subDays(180))->delete();
    DB::table('idempotency_keys')->where('expires_at', '<', now())->delete();
    DB::table('service_tokens')->where('expires_at', '<', now()->subDays(30))->delete();
    $this->info('Wartung abgeschlossen.');
})->purpose('Raeumt abgelaufene Sitzungen, Tokens, Nonces, Pairings und Setup-Admins auf (per Cron alle 5 Minuten)');

Artisan::command('login:status', function (SetupService $setup, KeyManager $keys) {
    $this->table(['Eigenschaft', 'Wert'], [
        ['Version', config('vylaris.version')],
        ['Issuer', config('vylaris.issuer')],
        ['Setup-Modus', $setup->mode()],
        ['Dash', Setting::get('dash.base_url', '-')],
        ['Aktiver Schluessel', $keys->active()?->kid ?? '-'],
        ['Aktive Clients', (string) DB::table('oidc_clients')->where('status', 'active')->count()],
        ['Aktive SSO-Sitzungen', (string) DB::table('sso_sessions')->whereNull('revoked_at')->where('expires_at', '>', now())->count()],
    ]);
})->purpose('Zeigt den Betriebszustand');

Artisan::command('login:backup {--keep=14}', function () {
    $dir = storage_path('backups');
    File::ensureDirectoryExists($dir, 0700);
    $data = ['schema' => 'vylaris-login-backup/1', 'created_at' => now()->toIso8601String(), 'version' => config('vylaris.version'), 'tables' => []];
    foreach (['settings', 'signing_keys', 'oidc_clients', 'sso_sessions', 'oidc_auth_codes', 'oidc_access_tokens', 'oidc_refresh_tokens', 'pairings', 'service_tokens', 'bootstrap_admins', 'recovery_tokens', 'audit_logs'] as $t) {
        $data['tables'][$t] = DB::table($t)->get()->map(fn ($r) => (array) $r)->all();
    }
    $file = $dir.'/login-'.now()->format('Ymd-His').'.json.gz';
    File::put($file, gzencode(json_encode($data, JSON_UNESCAPED_SLASHES), 9));
    @chmod($file, 0600);
    $files = collect(File::glob($dir.'/login-*.json.gz'))->sort()->values();
    $files->slice(0, max(0, $files->count() - (int) $this->option('keep')))->each(fn ($f) => File::delete($f));
    $this->info('Backup: '.$file.'  (Schluessel sind mit APP_KEY verschluesselt: APP_KEY separat sichern!)');
})->purpose('Sichert alle log_in-Daten (JSON, gzip, 0600)');

Artisan::command('login:restore {file} {--force}', function (string $file) {
    if (! $this->option('force') && ! $this->confirm('Alle aktuellen log_in-Daten werden ersetzt. Fortfahren?')) {
        return 1;
    }
    $data = json_decode((string) gzdecode((string) File::get($file)), true);
    if (($data['schema'] ?? null) !== 'vylaris-login-backup/1') {
        $this->error('Unbekanntes Backup-Format.');

        return 1;
    }
    DB::transaction(function () use ($data) {
        foreach ($data['tables'] as $t => $rows) {
            DB::table($t)->delete();
            foreach (array_chunk($rows, 200) as $chunk) {
                DB::table($t)->insert($chunk);
            }
        }
    });
    $this->info('Wiederhergestellt aus Backup vom '.$data['created_at'].' (Version '.$data['version'].').');
})->purpose('Stellt ein Backup wieder her');

// Fuer Hosting ohne Daemons: ein Cron-Eintrag "* * * * * php artisan schedule:run" genuegt.
Schedule::command('login:maintenance')->everyFiveMinutes();
Schedule::command('login:backup')->dailyAt('03:15');

Artisan::command('login:update:check', function (UpdateService $u) {
    $i = $u->check();
    $this->line('Installiert: '.$i['current'].'  Neueste Version: '.($i['latest'] ?? '-'));
    $this->info($i['update_available'] ? 'Update verfuegbar: php artisan login:update:apply' : 'Keine neuere Version.');
})->purpose('Prueft die GitHub-Releases von VylarisGroup/log_in auf Updates');

Artisan::command('login:update:apply', function (UpdateService $u) {
    try {
        $u->apply(fn (string $m) => $this->line($m));
    } catch (Throwable $e) {
        $this->error('Update fehlgeschlagen: '.$e->getMessage());

        return 1;
    }
})->purpose('Installiert das neueste Release (Backup, Pruefsumme, Migrationen, Rollback bei Fehler)');

Artisan::command('login:dash:revoke-tokens', function (ServiceTokens $tokens) {
    $n = $tokens->revokeAll();
    $this->warn("$n Service-Token widerrufen. Dash kann log_in nicht mehr verwalten, bis ueber einen Recovery-Link (login:recovery:issue) neu angebunden wird.");
})->purpose('Widerruft alle Service-Token der Dash-Installation (Notfall)');
