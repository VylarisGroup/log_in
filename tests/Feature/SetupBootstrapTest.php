<?php

namespace Tests\Feature;

use App\Models\BootstrapAdmin;
use App\Models\OidcClient;
use App\Models\RecoveryToken;
use App\Models\Setting;
use App\Services\Vylaris\SetupService;
use App\Services\Vylaris\Signer;
use App\Services\Vylaris\Totp;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Tests\DashTestCase;

/**
 * Bootstrap ohne Authentifizierungsschleife: log_in ist vor Dash startklar und nutzt nur lokale Einrichtungsmittel.
 */
class SetupBootstrapTest extends DashTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Frischinstallation: keine Dash-/Schluessel-Konfiguration vorhanden
        DB::table('settings')->delete();
        File::delete(storage_path('app/setup-token.txt'));
        File::deleteDirectory(storage_path('app/bootstrap'));
    }

    protected function tearDown(): void
    {
        File::delete(storage_path('app/setup-token.txt'));
        File::deleteDirectory(storage_path('app/bootstrap'));
        parent::tearDown();
    }

    private function token(): string
    {
        $this->get('/setup')->assertOk()->assertSee('Setup-Token');

        return trim(File::get(storage_path('app/setup-token.txt')));
    }

    private function enterToken(): void
    {
        $this->post('/setup/token', ['token' => $this->token()])->assertRedirect('/setup');
        $this->get('/setup')->assertOk(); // erzeugt das TOTP-Geheimnis fuer den Admin-Schritt
    }

    /** Fuehrt das komplette Setup durch und liefert [bundle, adminSecret]. */
    private function runWizard(): array
    {
        $this->enterToken();
        $secret = (string) session('setup_totp');
        $this->assertNotSame('', $secret);
        $this->post('/setup/admin', ['username' => 'setup-admin', 'password' => 'ein-sehr-langes-passwort', 'password_confirmation' => 'ein-sehr-langes-passwort', 'totp_code' => Totp::code($secret, intdiv(time(), 30))])->assertRedirect('/setup');
        $this->post('/setup/keys')->assertRedirect('/setup');

        // Dash laut Test-Fake entdecken, Fingerprint bestaetigen
        $this->post('/setup/dash/discover', ['dash_url' => 'https://dash.test'])->assertRedirect('/setup');
        $fp = Signer::fingerprint($this->dashKeys['public']);
        $this->post('/setup/dash/trust', ['fingerprint' => $fp])->assertRedirect('/setup');

        // Der Test-Fake kennt den log_in-Schluessel erst nach dem Setup: wie in Produktion importiert Dash das Bundle
        $this->post('/setup/client', ['redirect_uris' => "https://dash.test/auth/callback\n", 'post_logout_uris' => 'https://dash.test/'])->assertRedirect('/setup');
        $bundle = json_decode(File::get(storage_path('app/bootstrap/dash-bootstrap.json')), true);
        $this->loginKeys['public'] = $bundle['log_in_public_key']; // Dash importiert den log_in-Schluessel aus dem Bundle

        return [$bundle, $secret];
    }

    public function test_setup_requires_the_local_token_and_never_exposes_it(): void
    {
        $body = $this->get('/setup')->assertOk()->getContent();
        $token = trim(File::get(storage_path('app/setup-token.txt')));
        $this->assertSame(32, strlen($token));
        $this->assertStringNotContainsString($token, $body);
        $this->assertSame('0600', substr(sprintf('%o', fileperms(storage_path('app/setup-token.txt'))), -4));

        foreach (['/setup/admin', '/setup/keys', '/setup/dash/discover', '/setup/client', '/setup/test', '/setup/finish'] as $u) {
            $this->post($u, [])->assertForbidden();
        }
        $this->post('/setup/token', ['token' => 'falsch'])->assertSessionHasErrors('token');
    }

    public function test_setup_token_is_rate_limited(): void
    {
        $this->get('/setup');
        for ($i = 0; $i < 6; $i++) {
            $this->post('/setup/token', ['token' => 'falsch'.$i]);
        }
        $this->post('/setup/token', ['token' => trim(File::get(storage_path('app/setup-token.txt')))])->assertSessionHasErrors('token'); // selbst das richtige Token wird gesperrt
    }

    public function test_full_bootstrap_without_authentication_loop(): void
    {
        [$bundle] = $this->runWizard();

        $this->assertSame('https://login.test', $bundle['issuer']);
        $this->assertStringStartsWith('vl_dash_', $bundle['client_id']);
        $this->assertSame(Setting::get('login.sign_public'), $bundle['log_in_public_key']);
        $this->assertSame('0600', substr(sprintf('%o', fileperms(storage_path('app/bootstrap/dash-bootstrap.json'))), -4));

        // Verbindungstest: signierter Aufruf log_in -> Dash, kein Login/Session noetig
        $this->post('/setup/test')->assertRedirect('/setup')->assertSessionHas('status');
        $this->assertSame('1', Setting::get('setup.test_ok'));

        $this->post('/setup/finish')->assertRedirect('/setup')->assertSessionHas('status');
        $this->assertTrue(app(SetupService::class)->isCompleted());
        $this->assertSame('awaiting_dash_activation', Setting::get('setup.mode'));
        $this->assertFileDoesNotExist(storage_path('app/setup-token.txt'));

        // Nach Abschluss ist das Setup ohne Token/Admin/Recovery nicht mehr bedienbar
        $this->flushSession();
        $this->post('/setup/keys')->assertForbidden();
        $this->post('/setup/client', [])->assertForbidden();
        $this->get('/setup')->assertOk()->assertDontSee('Dash verbinden');

        // Dash meldet sich als erste OIDC-Anwendung an: Bootstrap endet automatisch
        $dash = OidcClient::query()->where('is_dash', true)->first();
        $this->assertSame('active', $dash->status);
        $this->assertSame(1, BootstrapAdmin::query()->whereNull('disabled_at')->count());
        $a = $this->loginAndAuthorize($dash);
        $this->exchange($dash, $bundle['client_secret'], $a['query']['code'], $a['verifier'])->assertOk();

        $this->assertSame('integrated', Setting::get('setup.mode'));
        $this->assertSame(0, BootstrapAdmin::query()->whereNull('disabled_at')->count());
        $this->assertSame('dash_activated', BootstrapAdmin::query()->first()->disabled_reason);
        $this->assertFileDoesNotExist(storage_path('app/bootstrap/dash-bootstrap.json'));
    }

    public function test_finish_is_refused_until_all_integrity_checks_pass(): void
    {
        $this->enterToken();
        $this->post('/setup/finish')->assertRedirect('/setup')->assertSessionHas('error');
        $this->assertFalse(app(SetupService::class)->isCompleted());
    }

    public function test_dash_trust_requires_matching_fingerprint(): void
    {
        $this->enterToken();
        $this->post('/setup/keys');
        $this->post('/setup/dash/discover', ['dash_url' => 'https://dash.test']);
        $this->post('/setup/dash/trust', ['fingerprint' => 'AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:0000:1111'])->assertSessionHasErrors('dash');
        $this->assertNull(Setting::get('dash.public_key'));
        $this->assertNull(Setting::get('setup.dash_done'));
    }

    public function test_dash_client_redirects_must_stay_on_dash_domain(): void
    {
        $this->enterToken();
        $this->post('/setup/keys');
        $this->post('/setup/dash/discover', ['dash_url' => 'https://dash.test']);
        $this->post('/setup/dash/trust', ['fingerprint' => Signer::fingerprint($this->dashKeys['public'])]);
        $this->post('/setup/client', ['redirect_uris' => 'https://evil.test/cb'])->assertSessionHasErrors('client');
        $this->assertSame(0, OidcClient::query()->count());
    }

    public function test_admin_needs_strong_password_valid_totp_and_is_single(): void
    {
        $this->enterToken();
        $secret = session('setup_totp');
        $code = Totp::code($secret, intdiv(time(), 30));
        $this->post('/setup/admin', ['username' => 'a', 'password' => 'kurz', 'password_confirmation' => 'kurz', 'totp_code' => $code])->assertSessionHasErrors('admin');
        $this->post('/setup/admin', ['username' => 'setup-admin', 'password' => 'ein-sehr-langes-passwort', 'password_confirmation' => 'ein-sehr-langes-passwort', 'totp_code' => '000000'])->assertSessionHasErrors('admin');
        $this->assertSame(0, BootstrapAdmin::query()->count());
        $this->post('/setup/admin', ['username' => 'setup-admin', 'password' => 'ein-sehr-langes-passwort', 'password_confirmation' => 'ein-sehr-langes-passwort', 'totp_code' => $code])->assertRedirect('/setup');
        $a = BootstrapAdmin::query()->first();
        $this->assertTrue($a->expires_at->between(now()->addHours(71), now()->addHours(73)));
        $this->assertStringNotContainsString('ein-sehr-langes', $a->password_hash);
        $this->assertNotSame($secret, $a->totp_secret_enc); // verschluesselt
        $this->assertSame($secret, Crypt::decryptString($a->totp_secret_enc));
    }

    public function test_maintenance_admin_login_lockout_expiry_and_totp(): void
    {
        [, $totp] = $this->runWizard();
        $this->post('/setup/test');
        $this->post('/setup/finish');
        $this->flushSession();
        $good = ['username' => 'setup-admin', 'password' => 'ein-sehr-langes-passwort', 'totp_code' => Totp::code($totp, intdiv(time(), 30))];

        $this->post('/setup/login', array_merge($good, ['password' => 'falsch']))->assertSessionHasErrors('login');
        $this->post('/setup/login', array_merge($good, ['totp_code' => '000000']))->assertSessionHasErrors('login');
        $this->post('/setup/keys')->assertForbidden();
        $this->post('/setup/login', $good)->assertRedirect('/setup');
        $this->get('/setup')->assertOk()->assertSee('Dash verbinden');

        // Ablauf: abgelaufener Admin wird abgewiesen
        $this->flushSession();
        BootstrapAdmin::query()->update(['expires_at' => now()->subMinute()]);
        $this->post('/setup/login', $good)->assertSessionHasErrors('login');
    }

    public function test_recovery_token_is_single_use_short_lived_and_cli_only(): void
    {
        $this->runWizard();
        $this->post('/setup/test');
        $this->post('/setup/finish');
        $this->flushSession();

        $this->get('/setup/recover/erfundenes-token-erfundenes-token-1234')->assertNotFound();
        $this->artisan('login:recovery:issue')->assertExitCode(0);
        $t = RecoveryToken::query()->first();
        $this->assertNotNull($t);
        // Klartext-Token liegt nirgends in der DB
        $plain = app(SetupService::class)->issueRecoveryToken();
        $this->assertStringNotContainsString($plain, json_encode(DB::table('recovery_tokens')->get()));

        $this->get('/setup/recover/'.$plain)->assertRedirect('/setup');
        $this->get('/setup')->assertOk()->assertSee('Dash verbinden');
        $this->flushSession();
        $this->get('/setup/recover/'.$plain)->assertNotFound(); // einmalig

        $plain2 = app(SetupService::class)->issueRecoveryToken();
        $this->travel(16)->minutes();
        $this->flushSession();
        $this->get('/setup/recover/'.$plain2)->assertNotFound(); // abgelaufen
    }

    public function test_no_default_credentials_or_backdoor_exist(): void
    {
        $this->assertSame(0, BootstrapAdmin::query()->count());
        $this->assertSame(0, DB::table('settings')->count());
        $this->post('/login', ['identifier' => 'admin', 'password' => 'admin'])->assertRedirect('/setup'); // ohne Dash kein Login
    }

    public function test_environment_checks_report_sodium_and_https(): void
    {
        $env = app(SetupService::class)->environment();
        $this->assertTrue($env['sodium']['ok']);
        $this->assertTrue($env['HTTPS']['ok']);
    }
}
