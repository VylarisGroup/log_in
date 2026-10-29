<?php

namespace Tests\Feature;

use App\Models\ServiceToken;
use App\Models\Setting;
use App\Models\SigningKey;
use App\Services\Dash\DashClient;
use App\Services\Dash\DashProtocolException;
use App\Services\Vylaris\ServiceTokens;
use App\Services\Vylaris\Signer;
use App\Services\Vylaris\SsrfGuard;
use Tests\DashTestCase;

/** Vereinheitlichter Vylaris-Vertrag: Bearer + Signatur, Fehlerformat, Idempotenz, Token-Lebenszyklus, SSRF. */
class MachineContractTest extends DashTestCase
{
    public function test_bearer_is_required_and_signature_alone_is_not_enough(): void
    {
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['token' => null])->assertStatus(401)->assertJsonPath('error.code', 'unauthorized');
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['token' => 'vlst_unbekannt'])->assertStatus(401)->assertJsonPath('error.code', 'invalid_token');
    }

    public function test_valid_bearer_with_bad_signature_is_rejected(): void
    {
        $other = Signer::generateKeypair();
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['secret' => $other['secret']])->assertStatus(401)->assertJsonPath('error.code', 'invalid_signature');
    }

    public function test_oidc_access_tokens_are_not_accepted_as_service_tokens(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['token' => $j['access_token']])->assertStatus(401)->assertJsonPath('error.code', 'invalid_token');
    }

    public function test_service_token_is_stored_hashed_only(): void
    {
        $this->assertDatabaseHas('service_tokens', ['token_hash' => hash('sha256', $this->dashToken)]);
        $this->assertDatabaseMissing('service_tokens', ['token_hash' => $this->dashToken]);
        $this->assertStringNotContainsString($this->dashOutboundToken, (string) Setting::get('dash.outbound_token')); // verschluesselt abgelegt
    }

    public function test_expired_revoked_and_installation_revoked_tokens(): void
    {
        ServiceToken::query()->update(['expires_at' => now()->subMinute()]);
        $this->dashApi('GET', '/api/vylaris/v1/health')->assertStatus(401)->assertJsonPath('error.code', 'token_expired');

        ServiceToken::query()->update(['expires_at' => now()->addDay(), 'status' => 'revoked', 'revoked_reason' => 'manual']);
        $this->dashApi('GET', '/api/vylaris/v1/health')->assertStatus(401)->assertJsonPath('error.code', 'invalid_token');

        ServiceToken::query()->update(['revoked_reason' => 'installation_revoked']);
        $this->dashApi('GET', '/api/vylaris/v1/health')->assertStatus(403)->assertJsonPath('error.code', 'installation_revoked');
    }

    public function test_missing_scope_is_forbidden_and_the_error_response_is_signed(): void
    {
        [$limited] = app(ServiceTokens::class)->issueInbound('dash-install-0001', ['service.health']);
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['token' => $limited])->assertOk();
        $r = $this->dashApi('GET', '/api/vylaris/v1/clients', null, ['token' => $limited])->assertStatus(403)->assertJsonPath('error.code', 'forbidden');
        $canon = Signer::responseCanonical(403, $this->lastDashNonce, (int) $r->headers->get('X-Vylaris-Timestamp'), $r->getContent());
        $this->assertTrue(Signer::verify($canon, $r->headers->get('X-Vylaris-Signature'), $this->loginKeys['public']));
        $this->assertSame('login-install-0001', $r->headers->get('X-Vylaris-Key-Id'));
    }

    public function test_error_format_and_unknown_paths_and_removed_legacy_paths(): void
    {
        $this->dashApi('GET', '/api/vylaris/v1/clients/gibt-es-nicht')->assertStatus(404)->assertJsonStructure(['error' => ['code', 'message']])->assertJsonPath('error.code', 'resource_not_found');
        $this->getJson('/api/vylaris/v1/gibt-es-nicht')->assertStatus(404)->assertJsonPath('error.code', 'resource_not_found');
        // Alte, konkurrierende Pfade existieren nicht mehr
        $this->getJson('/api/dash/v1/health')->assertStatus(404);
        $this->getJson('/api/v1/tools/self')->assertStatus(404);
    }

    public function test_discovery_is_public_and_unsigned_and_rate_limited(): void
    {
        $r = $this->getJson('/.well-known/vylaris-login')->assertOk()->assertJsonPath('data.api_version', 'v1')->assertJsonPath('data.public_key', $this->loginKeys['public']);
        $this->assertNull($r->headers->get('X-Vylaris-Signature'));
        $this->getJson('/api/vylaris/v1/discovery')->assertOk()->assertJsonPath('data.api_base', 'https://login.test/api/vylaris/v1');
        for ($i = 0; $i < 70; $i++) {
            $last = $this->getJson('/api/vylaris/v1/discovery');
        }
        $last->assertStatus(429)->assertJsonPath('error.code', 'rate_limited');
    }

    public function test_idempotency_key_replays_the_stored_response_and_detects_conflicts(): void
    {
        $key = 'idem-key-0001';
        $r1 = $this->dashApi('POST', '/api/vylaris/v1/keys/rotate', null, ['idempotency' => $key])->assertCreated();
        $r2 = $this->dashApi('POST', '/api/vylaris/v1/keys/rotate', null, ['idempotency' => $key])->assertCreated();
        $this->assertSame($r1->json('data.kid'), $r2->json('data.kid'));
        $this->assertSame('true', $r2->headers->get('Idempotent-Replayed'));
        $this->assertSame(1, SigningKey::query()->count()); // nur EINE Rotation trotz zweitem Aufruf

        // gleicher Schluessel, anderer Request
        $this->dashApi('POST', '/api/vylaris/v1/users/u-alice/revoke', ['reason' => 'x'], ['idempotency' => $key])->assertStatus(409)->assertJsonPath('error.code', 'idempotency_conflict');
        $this->dashApi('POST', '/api/vylaris/v1/keys/rotate', null, ['idempotency' => 'zu kurz!'])->assertStatus(422)->assertJsonPath('error.code', 'validation_failed');
    }

    public function test_token_rotation_delivers_sealed_tokens_and_switches_after_first_use(): void
    {
        $old = $this->dashToken;
        $oldOutbound = $this->dashOutboundToken;
        $r = $this->dashApi('POST', '/api/vylaris/v1/service-tokens/rotate')->assertOk();
        $this->assertStringNotContainsString('vlst_', $r->getContent()); // nie im Klartext
        $new = json_decode(Signer::unseal($r->json('data.sealed_tokens'), $this->dashBox['secret'], $this->dashBox['public']), true);
        $this->assertNotSame($old, $new['service_token']);
        $this->assertNotSame($oldOutbound, $new['login_to_dash_token']);

        // Bis zur ersten Nutzung des neuen Tokens sendet log_in noch mit dem alten Outbound-Token
        $this->assertSame($oldOutbound, app(ServiceTokens::class)->outbound());
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['token' => $new['service_token']])->assertOk(); // Empfangsbestaetigung
        $this->assertSame($new['login_to_dash_token'], app(ServiceTokens::class)->outbound());

        // Uebergangsphase: altes Token noch kurz gueltig, danach abgelaufen
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['token' => $old])->assertOk();
        $this->travel(11)->minutes();
        $this->dashApi('GET', '/api/vylaris/v1/health', null, ['token' => $old])->assertStatus(401)->assertJsonPath('error.code', 'token_expired');
    }

    public function test_token_rotation_requires_dash_box_key(): void
    {
        Setting::forget('dash.box_public_key');
        $this->dashApi('POST', '/api/vylaris/v1/service-tokens/rotate')->assertStatus(422)->assertJsonPath('error.code', 'validation_failed');
    }

    public function test_outbound_requests_carry_bearer_and_dash_rejecting_it_is_not_a_success(): void
    {
        $this->assertSame('ok', app(DashClient::class)->health()['status']);
        $this->dashOutboundToken = 'vlst_anderes';
        $this->expectException(DashProtocolException::class);
        app(DashClient::class)->health();
    }

    public function test_ssrf_guard_blocks_unsafe_targets(): void
    {
        config(['vylaris.ssrf.enforce' => true, 'vylaris.ssrf.allow_private' => false, 'vylaris.dash.allow_http' => false]);
        foreach (['https://127.0.0.1', 'https://10.0.0.5', 'https://192.168.1.10', 'https://172.16.0.1', 'https://169.254.169.254/latest', 'https://[::1]', 'https://100.64.0.1', 'https://[fd00::1]', 'https://[::ffff:127.0.0.1]', 'http://8.8.8.8', 'https://user:pw@8.8.8.8', 'ftp://8.8.8.8', 'https://0.0.0.0'] as $url) {
            try {
                SsrfGuard::check($url);
                $this->fail("$url wurde nicht blockiert");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->assertSame('8.8.8.8', SsrfGuard::check('https://8.8.8.8')['host']);

        $this->expectException(DashProtocolException::class);
        app(DashClient::class)->discover('https://127.0.0.1');
    }

    public function test_ssrf_relaxations_are_ignored_in_production(): void
    {
        config(['vylaris.ssrf.enforce' => false, 'vylaris.ssrf.allow_private' => true, 'vylaris.dash.allow_http' => true]);
        $this->assertTrue(SsrfGuard::relaxed()); // Entwicklung/Test
        $this->app->detectEnvironment(fn () => 'production');
        $this->assertFalse(SsrfGuard::relaxed());
        $this->expectException(\InvalidArgumentException::class);
        SsrfGuard::check('https://10.0.0.1');
    }
}
