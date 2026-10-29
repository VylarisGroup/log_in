<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureInstalled;
use App\Models\BootstrapAdmin;
use App\Models\OidcClient;
use App\Models\Setting;
use App\Services\Dash\DashClient;
use App\Services\Dash\DashProtocolException;
use App\Services\Vylaris\Signer;
use App\Services\Vylaris\Totp;
use App\Support\EnvFile;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Schema;
use Tests\DashTestCase;

/** Ein-Klick-Installer: .env-Provisionierung, Installation, automatische Dash-Registrierung, Bundle, Pseudo-Cron. */
class InstallerTest extends DashTestCase
{
    private string $envFile;

    protected function setUp(): void
    {
        parent::setUp();
        DB::table('settings')->delete();
        File::delete(storage_path('app/setup-token.txt'));
        File::deleteDirectory(storage_path('app/bootstrap'));
        $this->envFile = tempnam(sys_get_temp_dir(), 'env');
        file_put_contents($this->envFile, "APP_NAME=Test\n");
        config(['vylaris.env_path' => $this->envFile]); // die echte .env bleibt unberuehrt
    }

    protected function tearDown(): void
    {
        @unlink($this->envFile);
        File::delete(storage_path('app/setup-token.txt'));
        File::deleteDirectory(storage_path('app/bootstrap'));
        EnsureInstalled::reset();
        parent::tearDown();
    }

    private function enterSetup(): string
    {
        $this->get('/setup')->assertOk();
        $this->post('/setup/token', ['token' => trim(File::get(storage_path('app/setup-token.txt')))])->assertRedirect('/setup');
        $this->get('/setup')->assertOk();

        return (string) session('setup_totp');
    }

    /** @return array<string, string> */
    private function installForm(string $secret, array $over = []): array
    {
        return $over + ['issuer' => 'https://login.example.org', 'db_mode' => 'sqlite', 'username' => 'setup-admin', 'password' => 'ein-sehr-langes-passwort', 'password_confirmation' => 'ein-sehr-langes-passwort', 'totp_code' => Totp::code($secret, intdiv(time(), 30))];
    }

    public function test_env_file_sets_replaces_quotes_and_rejects_newlines(): void
    {
        file_put_contents($this->envFile, "A=1\nB=2\n");
        EnvFile::set(['A' => 'neu', 'C' => 'mit Leerzeichen $x'], $this->envFile);
        $c = file_get_contents($this->envFile);
        $this->assertStringContainsString("A=neu\n", $c);
        $this->assertStringContainsString("B=2\n", $c);
        $this->assertStringContainsString('C="mit Leerzeichen \\$x"', $c);
        $this->expectException(\InvalidArgumentException::class);
        EnvFile::set(['D' => "x\nEVIL=1"], $this->envFile);
    }

    public function test_provision_creates_a_working_env_once_and_keeps_an_existing_key(): void
    {
        $dir = sys_get_temp_dir().'/vl-prov-'.bin2hex(random_bytes(4));
        mkdir($dir.'/database', 0777, true);
        copy(base_path('.env.example'), $dir.'/.env.example');

        EnvFile::provision($dir, 'login.example.org', true);
        $env = file_get_contents($dir.'/.env');
        $this->assertMatchesRegularExpression('/^APP_KEY=base64:\S{43}=$/m', $env);
        $this->assertStringContainsString('APP_URL=https://login.example.org', $env);
        $this->assertStringContainsString('OIDC_ISSUER=https://login.example.org', $env);
        $this->assertStringContainsString('DB_CONNECTION=sqlite', $env);
        $this->assertStringContainsString('SESSION_DRIVER=file', $env);
        $this->assertFileExists($dir.'/database/database.sqlite');

        EnvFile::provision($dir, 'other.example.org', true); // zweiter Aufruf aendert nichts
        $this->assertSame($env, file_get_contents($dir.'/.env'));

        File::deleteDirectory($dir);
    }

    public function test_install_sets_up_admin_keys_and_issuer_without_touching_the_real_env(): void
    {
        $secret = $this->enterSetup();
        $this->post('/setup/install', $this->installForm($secret))->assertRedirect('/setup')->assertSessionHasNoErrors();

        $this->assertSame('1', Setting::get('setup.admin_done'));
        $this->assertSame('1', Setting::get('setup.keys_done'));
        $this->assertSame(1, BootstrapAdmin::query()->count());
        $this->assertSame('https://login.example.org', config('vylaris.issuer'));
        $this->assertStringContainsString('OIDC_ISSUER=https://login.example.org', file_get_contents($this->envFile));
    }

    public function test_install_rejects_weak_password_and_wrong_totp_before_changing_anything(): void
    {
        $secret = $this->enterSetup();
        $this->post('/setup/install', $this->installForm($secret, ['password' => 'kurz', 'password_confirmation' => 'kurz']))->assertSessionHasErrors('install');
        $this->post('/setup/install', $this->installForm($secret, ['totp_code' => '000000']))->assertSessionHasErrors('install');
        $this->post('/setup/install', $this->installForm($secret, ['issuer' => 'http://nope.example.org']))->assertSessionHasErrors('install');
        $this->assertSame(0, BootstrapAdmin::query()->count());
        $this->assertStringNotContainsString('OIDC_ISSUER', file_get_contents($this->envFile));
    }

    public function test_install_needs_the_setup_token_session(): void
    {
        $this->post('/setup/install', ['username' => 'x'])->assertRedirect('/setup')->assertSessionHas('error');
        $this->get('/setup/bundle')->assertNotFound();
    }

    public function test_trusting_dash_registers_it_automatically_and_the_bundle_can_be_downloaded(): void
    {
        $secret = $this->enterSetup();
        $this->post('/setup/install', $this->installForm($secret, ['issuer' => '']))->assertRedirect('/setup');
        $this->post('/setup/dash/discover', ['dash_url' => 'https://dash.test'])->assertRedirect('/setup');
        $this->post('/setup/dash/trust', ['fingerprint' => Signer::fingerprint($this->dashKeys['public'])])->assertRedirect('/setup');

        $client = OidcClient::query()->where('is_dash', true)->sole();
        $this->assertSame(['https://dash.test/auth/callback'], $client->redirect_uris);
        $this->assertSame('1', Setting::get('setup.client_done'));

        $res = $this->get('/setup/bundle')->assertOk()->assertHeader('Content-Disposition');
        $bundle = json_decode($res->streamedContent() ?: File::get(storage_path('app/bootstrap/dash-bootstrap.json')), true);
        $this->assertSame('vylaris-login-bootstrap/2', $bundle['schema']);
        $this->assertSame($client->client_id, $bundle['client_id']);
        $this->assertStringStartsWith('vlst_', $bundle['service_token']);
        // das Geheimnis wird nicht im Browser angezeigt
        $this->get('/setup')->assertOk()->assertDontSee($bundle['client_secret'])->assertDontSee($bundle['service_token']);
    }

    public function test_finish_runs_the_connection_test_itself(): void
    {
        $secret = $this->enterSetup();
        $this->post('/setup/install', $this->installForm($secret, ['issuer' => '']));
        $this->post('/setup/dash/discover', ['dash_url' => 'https://dash.test']);
        $this->post('/setup/dash/trust', ['fingerprint' => Signer::fingerprint($this->dashKeys['public'])]);
        $bundle = json_decode(File::get(storage_path('app/bootstrap/dash-bootstrap.json')), true);
        $this->loginKeys['public'] = $bundle['log_in_public_key'];
        $this->dashToken = $bundle['service_token'];
        $this->dashOutboundToken = $bundle['login_to_dash_token'];

        $this->assertNull(Setting::get('setup.test_ok'));
        $this->post('/setup/finish')->assertRedirect('/setup');
        $this->assertSame('1', Setting::get('setup.completed'));
        $this->assertSame('awaiting_dash_activation', Setting::get('setup.mode'));
    }

    public function test_discovery_accepts_keys_array_base64url_and_derives_the_api_version(): void
    {
        $raw = base64_decode($this->dashKeys['public']);
        $this->dashDiscoveryOverride = [
            'installation_id' => 'dash-legacy', 'name' => 'Dash',
            'api_base' => 'https://dash.test/api/vylaris/v1',
            'keys' => [['alg' => 'EdDSA', 'status' => 'active', 'public_key' => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=')]],
        ];
        $d = app(DashClient::class)->discover('https://dash.test');
        $this->assertSame($this->dashKeys['public'], $d['public_key']);
        $this->assertSame('v1', $d['api_version']);
    }

    public function test_discovery_accepts_the_data_envelope(): void
    {
        $this->dashDiscoveryOverride = ['data' => ['api_version' => '1', 'installation_id' => 'd', 'name' => 'Dash', 'public_key' => $this->dashKeys['public']]];
        $this->assertSame('v1', app(DashClient::class)->discover('https://dash.test')['api_version']);
    }

    public function test_discovery_errors_name_the_missing_fields_and_the_wrong_version(): void
    {
        $this->dashDiscoveryOverride = ['protocol' => 'x', 'name' => 'Dash', 'installation_id' => 'd', 'api_base' => 'https://dash.test/api/v1'];
        try {
            app(DashClient::class)->discover('https://dash.test');
            $this->fail('keine Ausnahme');
        } catch (DashProtocolException $e) {
            $this->assertStringContainsString('es fehlt: public_key', $e->getMessage());
        }
        $this->dashDiscoveryOverride = ['api_version' => 'v2', 'name' => 'Dash', 'installation_id' => 'd', 'public_key' => $this->dashKeys['public']];
        $this->expectException(DashProtocolException::class);
        $this->expectExceptionMessageMatches('/API-Version v2/');
        app(DashClient::class)->discover('https://dash.test');
    }

    public function test_without_database_web_requests_go_to_setup_and_api_returns_503(): void
    {
        Schema::drop('settings');
        EnsureInstalled::reset();
        $this->get('/login')->assertRedirect('/setup');
        $this->getJson('/api/vylaris/v1/health')->assertStatus(503)->assertJsonPath('error.code', 'service_unavailable');
        $this->get('/setup')->assertOk(); // der Assistent selbst bleibt erreichbar
    }

    public function test_pseudo_cron_runs_due_tasks_at_most_once_per_minute(): void
    {
        config(['vylaris.pseudo_cron' => true]);
        Cache::forget('vylaris:pseudo-cron');
        $this->get('/.well-known/openid-configuration');
        $this->assertTrue(Cache::has('vylaris:pseudo-cron'));

        config(['vylaris.pseudo_cron' => false]);
        Cache::forget('vylaris:pseudo-cron');
        $this->get('/.well-known/openid-configuration');
        $this->assertFalse(Cache::has('vylaris:pseudo-cron'));
    }
}
