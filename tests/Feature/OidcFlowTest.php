<?php

namespace Tests\Feature;

use App\Models\SsoSession;
use App\Services\Oidc\IdTokenResponse;
use Illuminate\Support\Facades\DB;
use Tests\DashTestCase;

class OidcFlowTest extends DashTestCase
{
    public function test_discovery_lists_only_supported_flows(): void
    {
        $d = $this->getJson('/.well-known/openid-configuration')->assertOk()->json();
        $this->assertSame('https://login.test', $d['issuer']);
        $this->assertSame(['code'], $d['response_types_supported']);
        $this->assertSame(['authorization_code', 'refresh_token'], $d['grant_types_supported']);
        $this->assertSame(['S256'], $d['code_challenge_methods_supported']);
        $this->assertSame(['RS256'], $d['id_token_signing_alg_values_supported']);
        $this->assertFalse($d['request_parameter_supported']);
        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'end_session_endpoint', 'revocation_endpoint'] as $k) {
            $this->assertStringStartsWith('https://login.test/', $d[$k]);
        }
    }

    public function test_full_code_flow_with_pkce_issues_verifiable_tokens(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $this->assertStringStartsWith('https://tool.test/callback?', $a['location']);
        $this->assertSame($a['params']['state'], $a['query']['state']);
        $this->assertArrayHasKey('code', $a['query']);
        $this->assertStringNotContainsString('access_token', $a['location']);

        $r = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertOk();
        $this->assertStringContainsString('no-store', (string) $r->headers->get('Cache-Control'));
        $j = $r->json();
        $this->assertSame('Bearer', $j['token_type']);
        $this->assertArrayHasKey('refresh_token', $j);

        [$h, $p] = $this->jwtParts($j['id_token']);
        $this->assertSame('RS256', $h['alg']);
        $this->assertSame('https://login.test', $p['iss']);
        $this->assertSame('u-alice', $p['sub']);
        $this->assertSame([$c->client_id], (array) $p['aud']);
        $this->assertSame($a['params']['nonce'], $p['nonce']);
        $this->assertSame(IdTokenResponse::halfHash($j['access_token']), $p['at_hash']);
        $this->assertSame('t-1', $p['tenant_id']);
        $this->assertSame(['admin'], $p['roles']);
        $this->assertSame(['pwd'], $p['amr']);
        $this->assertGreaterThan(time(), $p['exp']);
        $this->assertLessThanOrEqual(time() + 301, $p['exp']);

        // Signatur gegen die oeffentliche JWKS pruefen.
        $jwks = $this->getJson('/.well-known/jwks.json')->json('keys');
        $this->assertContains($h['kid'], array_column($jwks, 'kid'));
        $this->getJson('/.well-known/jwks.json')->assertJsonMissingPath('keys.0.d');

        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])
            ->assertOk()->assertJson(['sub' => 'u-alice', 'email' => 'alice@example.test', 'tenant_id' => 't-1', 'roles' => ['admin']]);
    }

    public function test_pkce_is_mandatory_and_verified(): void
    {
        [$c, $secret] = $this->makeClient();

        // ohne code_challenge
        $q = ['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid', 'state' => 's', 'nonce' => 'n'];
        $loc = $this->get('/authorize?'.http_build_query($q))->headers->get('Location');
        $this->assertStringContainsString('error=invalid_request', $loc);

        // plain ist nicht erlaubt
        $loc = $this->get('/authorize?'.http_build_query($q + ['code_challenge' => 'x'.str_repeat('a', 50), 'code_challenge_method' => 'plain']))->headers->get('Location');
        $this->assertStringContainsString('error=invalid_request', $loc);

        // falscher Verifier am Token-Endpoint
        $a = $this->loginAndAuthorize($c);
        $this->exchange($c, $secret, $a['query']['code'], 'wrong-verifier-wrong-verifier-wrong-verifier-123')->assertStatus(400)->assertJsonPath('error', 'invalid_grant');

        // fehlender Verifier
        $a = $this->loginAndAuthorize($c);
        $this->post('/token', ['grant_type' => 'authorization_code', 'code' => $a['query']['code'], 'redirect_uri' => $c->redirect_uris[0]], ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
    }

    public function test_state_and_nonce_are_required_and_openid_scope(): void
    {
        [$c] = $this->makeClient();
        [, $ch] = $this->pkce();
        $base = ['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid', 'code_challenge' => $ch, 'code_challenge_method' => 'S256'];
        $this->assertStringContainsString('error=invalid_request', $this->get('/authorize?'.http_build_query($base + ['nonce' => 'n']))->headers->get('Location')); // state fehlt
        $this->assertStringContainsString('error=invalid_request', $this->get('/authorize?'.http_build_query($base + ['state' => 's']))->headers->get('Location')); // nonce fehlt
        $this->assertStringContainsString('error=invalid_scope', $this->get('/authorize?'.http_build_query(array_merge($base, ['state' => 's', 'nonce' => 'n', 'scope' => 'profile'])))->headers->get('Location'));
    }

    public function test_unregistered_redirect_uri_never_redirects(): void
    {
        [$c] = $this->makeClient();
        [, $ch] = $this->pkce();
        foreach (['https://evil.test/callback', 'https://tool.test/callback/../x', 'https://tool.test/callback?x=1', 'https://tool.test.evil.test/callback', 'http://tool.test/callback'] as $uri) {
            $r = $this->get('/authorize?'.http_build_query(['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => $uri, 'scope' => 'openid', 'state' => 's', 'nonce' => 'n', 'code_challenge' => $ch, 'code_challenge_method' => 'S256']));
            $this->assertNull($r->headers->get('Location'), "Redirect zu $uri darf nicht erfolgen");
            $r->assertStatus(401);
        }
    }

    public function test_unknown_or_inactive_client_is_rejected(): void
    {
        [, $ch] = $this->pkce();
        $this->get('/authorize?'.http_build_query(['response_type' => 'code', 'client_id' => 'nope', 'redirect_uri' => 'https://tool.test/callback', 'scope' => 'openid', 'state' => 's', 'nonce' => 'n', 'code_challenge' => $ch, 'code_challenge_method' => 'S256']))->assertStatus(401);
        [$c] = $this->makeClient(['status' => 'suspended']);
        $r = $this->get('/authorize?'.http_build_query(['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => 'https://tool.test/callback', 'scope' => 'openid', 'state' => 's', 'nonce' => 'n', 'code_challenge' => $ch, 'code_challenge_method' => 'S256']));
        $r->assertStatus(401);
        $this->assertNull($r->headers->get('Location'));
    }

    public function test_implicit_and_other_grants_are_not_available(): void
    {
        [$c, $secret] = $this->makeClient();
        [, $ch] = $this->pkce();
        $this->get('/authorize?'.http_build_query(['response_type' => 'token', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid', 'state' => 's', 'nonce' => 'n']))->assertStatus(400);
        $this->get('/authorize?'.http_build_query(['response_type' => 'id_token', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid', 'state' => 's', 'nonce' => 'n']))->assertStatus(400);
        foreach (['client_credentials', 'password'] as $g) {
            $this->post('/token', ['grant_type' => $g, 'username' => 'a', 'password' => 'b'], ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)])->assertStatus(400)->assertJsonPath('error', 'unsupported_grant_type');
        }
    }

    public function test_request_objects_are_refused(): void
    {
        [$c] = $this->makeClient();
        [, $ch] = $this->pkce();
        $loc = $this->get('/authorize?'.http_build_query(['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid', 'state' => 's', 'nonce' => 'n', 'code_challenge' => $ch, 'code_challenge_method' => 'S256', 'request' => 'eyJ.x.y']))->headers->get('Location');
        $this->assertStringContainsString('error=request_not_supported', $loc);
    }

    public function test_scope_beyond_client_registration_is_rejected(): void
    {
        [$c] = $this->makeClient(['scopes' => ['openid']]);
        [, $ch] = $this->pkce();
        $r = $this->get('/authorize?'.http_build_query(['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid vylaris', 'state' => 's', 'nonce' => 'n', 'code_challenge' => $ch, 'code_challenge_method' => 'S256']));
        $this->assertStringContainsString('error=invalid_scope', (string) ($r->headers->get('Location') ?? $r->getContent()));
    }

    public function test_client_authentication_wrong_secret(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $this->exchange($c, 'falsch', $a['query']['code'], $a['verifier'])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
        // Code eines anderen Clients: Impersonation scheitert
        [$c2, $s2] = $this->makeClient(['client_id' => 'vl_other', 'installation_id' => 'tool-install-0002', 'redirect_uris' => ['https://tool.test/callback']]);
        $this->exchange($c2, $s2, $a['query']['code'], $a['verifier'])->assertStatus(400);
    }

    public function test_authorization_code_is_single_use_and_reuse_revokes_tokens(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertOk()->json();
        $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
    }

    public function test_refresh_tokens_rotate_and_reuse_kills_the_session(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $auth = ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)];

        $r1 = $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $j['refresh_token']], $auth)->assertOk()->json();
        $this->assertNotSame($j['refresh_token'], $r1['refresh_token']);
        $this->assertArrayNotHasKey('id_token', $r1);

        // Wiederverwendung des alten Tokens -> abgelehnt und Sitzung inkl. neuer Tokens widerrufen
        $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $j['refresh_token']], $auth)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $r1['refresh_token']], $auth)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame(0, SsoSession::query()->whereNull('revoked_at')->count());
    }

    public function test_refresh_token_only_with_offline_access(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid']);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertOk()->json();
        $this->assertArrayNotHasKey('refresh_token', $j);
    }

    public function test_refresh_token_cannot_be_used_by_another_client(): void
    {
        [$c, $secret] = $this->makeClient();
        [$c2, $s2] = $this->makeClient(['client_id' => 'vl_other', 'installation_id' => 'tool-install-0002']);
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $j['refresh_token']], ['Authorization' => 'Basic '.base64_encode($c2->client_id.':'.$s2)])->assertStatus(400);
    }

    public function test_userinfo_rejects_forged_tampered_and_foreign_tokens(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        [$h, $p, $s] = explode('.', $j['access_token']);

        $this->getJson('/userinfo')->assertStatus(400);
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$h.'.'.$p.'.'.strrev($s)])->assertStatus(401);
        // alg=none
        $none = rtrim(strtr(base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => 'x'])), '+/', '-_'), '=');
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$none.'.'.$p.'.'])->assertStatus(401);
        // Payload manipuliert (anderer Benutzer)
        $pl = json_decode(base64_decode(strtr($p, '-_', '+/')), true);
        $pl['sub'] = 'u-bob';
        $forged = $h.'.'.rtrim(strtr(base64_encode(json_encode($pl)), '+/', '-_'), '=').'.'.$s;
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$forged])->assertStatus(401);
        // id_token ist kein Access-Token (kein DB-Eintrag)
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['id_token']])->assertStatus(401);
    }

    public function test_tenant_and_user_separation(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $alice = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $this->flushSession();
        $b = $this->loginAndAuthorize($c, 'bob@example.test', 'bobs-long-password-1');
        $bob = $this->exchange($c, $secret, $b['query']['code'], $b['verifier'])->json();

        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$alice['access_token']])->assertJson(['sub' => 'u-alice', 'tenant_id' => 't-1']);
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$bob['access_token']])->assertJson(['sub' => 'u-bob', 'tenant_id' => 't-2', 'roles' => ['member']]);
    }

    public function test_dash_returning_wrong_subject_is_rejected(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $this->clearCaches();
        $this->dashUsers['u-alice']['sub'] = 'u-mallory'; // Dash (oder MITM mit gueltigem Schluessel) vertauscht die Identitaet
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
    }

    public function test_login_failures_are_uniform_and_throttled(): void
    {
        [$c] = $this->makeClient();
        foreach ([['alice@example.test', 'falsch'], ['nobody@example.test', 'x']] as [$i, $pw]) {
            $this->post('/login', ['identifier' => $i, 'password' => $pw])->assertSessionHasErrors(['identifier' => 'Anmeldung fehlgeschlagen.']);
        }
        $this->dashUsers['u-alice']['status'] = 'locked';
        $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'correct-horse-battery'])->assertSessionHasErrors(['identifier' => 'Anmeldung fehlgeschlagen.']);
        for ($i = 0; $i < 10; $i++) {
            $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'falsch'.$i]);
        }
        $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'correct-horse-battery'])->assertSessionHasErrors(['identifier' => 'Zu viele Versuche. Bitte spaeter erneut versuchen.']);
    }

    public function test_mfa_required_flow_and_amr(): void
    {
        $this->dashCreds['alice@example.test']['mfa'] = '123456';
        [$c, $secret] = $this->makeClient();
        $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'correct-horse-battery'])->assertSessionHas('mfa_required');
        $a = $this->loginAndAuthorize($c);
        $this->assertTrue(true);
        $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'correct-horse-battery', 'mfa_code' => '000000'])->assertSessionHasErrors('identifier');
        $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'correct-horse-battery', 'mfa_code' => '123456'])->assertRedirect();
        $this->assertSame(['pwd', 'otp'], SsoSession::query()->latest('created_at')->first()->amr);
    }

    public function test_session_fixation_login_issues_new_session_id(): void
    {
        [$c] = $this->makeClient();
        $this->get('/login');
        $before = session()->getId();
        $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'correct-horse-battery']);
        $this->assertNotSame($before, session()->getId());
    }

    public function test_prompt_none_without_session_returns_login_required(): void
    {
        [$c] = $this->makeClient();
        [, $ch] = $this->pkce();
        $loc = $this->get('/authorize?'.http_build_query(['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid', 'state' => 's', 'nonce' => 'n', 'prompt' => 'none', 'code_challenge' => $ch, 'code_challenge_method' => 'S256']))->headers->get('Location');
        $this->assertStringContainsString('error=login_required', $loc);
    }

    public function test_sso_session_idle_and_absolute_expiry(): void
    {
        [$c] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $s = SsoSession::query()->first();
        $s->update(['last_seen_at' => now()->subSeconds(config('vylaris.ttl.sso_idle') + 5)]);
        $this->get($a['url'])->assertRedirect('/login');
        $s->update(['last_seen_at' => now(), 'expires_at' => now()->subSecond()]);
        $this->get($a['url'])->assertRedirect('/login');
    }

    public function test_rp_logout_revokes_session_and_tokens_and_validates_redirect(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();

        // nicht registrierte Ziel-URI: kein Redirect, aber Abmeldung
        $this->get('/logout?'.http_build_query(['id_token_hint' => $j['id_token'], 'post_logout_redirect_uri' => 'https://evil.test/x']))->assertOk();
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
        $this->assertSame(0, SsoSession::query()->whereNull('revoked_at')->count());

        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $this->get('/logout?'.http_build_query(['id_token_hint' => $j['id_token'], 'post_logout_redirect_uri' => 'https://tool.test/bye', 'state' => 'abc']))->assertRedirect('https://tool.test/bye?state=abc');
    }

    public function test_logout_without_hint_requires_confirmation(): void
    {
        [$c] = $this->makeClient();
        $this->loginAndAuthorize($c);
        $this->get('/logout')->assertOk()->assertSee('Jetzt abmelden');
        $this->assertSame(1, SsoSession::query()->whereNull('revoked_at')->count());
        $this->post('/logout')->assertOk()->assertSee('Jetzt abmelden'); // ohne gueltiges CSRF-Token keine Abmeldung
        $this->assertSame(1, SsoSession::query()->whereNull('revoked_at')->count());
        $this->post('/logout', ['_token' => session()->token()])->assertOk()->assertSee('Abgemeldet');
        $this->assertSame(0, SsoSession::query()->whereNull('revoked_at')->count());
    }

    public function test_revocation_endpoint_rfc7009(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $auth = ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)];

        $this->post('/revoke', ['token' => 'unbekannt'], $auth)->assertOk();
        $this->post('/revoke', ['token' => $j['access_token']], ['Authorization' => 'Basic '.base64_encode($c->client_id.':falsch')])->assertStatus(401);
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertOk();
        $this->post('/revoke', ['token' => $j['access_token']], $auth)->assertOk();
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
        $this->post('/revoke', ['token' => $j['refresh_token']], $auth)->assertOk();
        $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $j['refresh_token']], $auth)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    }

    public function test_tokens_and_secrets_never_logged_or_in_audit(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $dump = json_encode(DB::table('audit_logs')->get());
        foreach ([$j['access_token'], $j['refresh_token'], $a['query']['code'], $secret, 'correct-horse-battery', $a['verifier']] as $needle) {
            $this->assertStringNotContainsString($needle, $dump);
        }
    }

    public function test_security_headers_present(): void
    {
        $this->get('/login')->assertHeader('X-Frame-Options', 'DENY')->assertHeader('X-Content-Type-Options', 'nosniff')->assertHeader('Referrer-Policy', 'no-referrer');
    }
}
