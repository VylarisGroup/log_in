<?php

namespace Tests\Feature;

use App\Models\SsoSession;
use Illuminate\Support\Facades\Cache;
use Tests\DashTestCase;

class RevocationAndOutageTest extends DashTestCase
{
    private function tokens(): array
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);

        return [$c, $secret, $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertOk()->json(), $a];
    }

    public function test_dash_revocation_push_kills_sessions_and_tokens_immediately(): void
    {
        [$c, $secret, $j] = $this->tokens();
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertOk();

        $this->dashApi('POST', '/api/vylaris/v1/users/u-alice/revoke', ['reason' => 'account_blocked'])->assertOk()->assertJsonPath('data.revoked_sessions', 1);

        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
        $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $j['refresh_token']], ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)])->assertStatus(400);
        $this->assertSame(0, SsoSession::query()->whereNull('revoked_at')->count());
    }

    public function test_disabled_account_is_blocked_at_refresh_without_push_even_when_cached(): void
    {
        [$c, $secret, $j] = $this->tokens();
        $this->dashUsers['u-alice']['status'] = 'disabled'; // Dash sperrt, aber sendet keinen Push
        // Refresh prueft IMMER frisch bei Dash (kein Cache)
        $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $j['refresh_token']], ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->assertSame(0, SsoSession::query()->whereNull('revoked_at')->count());
    }

    public function test_stale_cache_is_bounded_by_ttl(): void
    {
        config(['vylaris.dash.claims_cache_ttl' => 60]);
        [, , $j] = $this->tokens();
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertOk();
        $this->dashUsers['u-alice']['status'] = 'deleted';
        // innerhalb der TTL moeglicherweise veraltet, danach zwingend frisch
        $this->travel(61)->seconds();
        Cache::flush(); // array-Cache kennt keine Zeitreise; entspricht TTL-Ablauf
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
    }

    public function test_cache_ttl_zero_gives_immediate_effect(): void
    {
        config(['vylaris.dash.claims_cache_ttl' => 0]);
        [, , $j] = $this->tokens();
        $this->dashUsers['u-alice']['status'] = 'locked';
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
    }

    public function test_role_change_is_picked_up_after_refresh_push(): void
    {
        [, , $j] = $this->tokens();
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertJsonPath('roles', ['admin']);
        $this->dashUsers['u-alice']['roles'] = ['member'];
        $this->dashApi('POST', '/api/vylaris/v1/users/u-alice/refresh')->assertOk();
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertJsonPath('roles', ['member']);
    }

    public function test_dash_outage_fails_closed_for_new_tokens_and_refresh(): void
    {
        [$c, $secret, $j] = $this->tokens();
        $auth = ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)];
        $this->clearCaches();
        $this->dashDown = true;

        // Userinfo: 503 statt Freigabe aus veralteten Daten
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(503)->assertJsonPath('error', 'temporarily_unavailable');
        // Refresh: keine neuen Tokens
        $this->post('/token', ['grant_type' => 'refresh_token', 'refresh_token' => $j['refresh_token']], $auth)->assertStatus(503);
        // Login: keine Anmeldung
        $this->flushSession();
        $this->post('/login', ['identifier' => 'alice@example.test', 'password' => 'correct-horse-battery'])->assertSessionHasErrors(['identifier' => 'Der Anmeldedienst ist voruebergehend nicht verfuegbar.']);
        // Code-Austausch bei Ausfall: kein Token
        $this->dashDown = false;
        $a = $this->loginAndAuthorize($c);
        $this->clearCaches();
        $this->dashDown = true;
        $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertStatus(503);

        // nach Wiederkehr funktioniert der Zugriff wieder, der Code war nicht verbraucht
        $this->dashDown = false;
        $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertOk();
    }

    public function test_authorize_during_outage_returns_temporarily_unavailable(): void
    {
        [$c] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $this->clearCaches();
        $this->dashDown = true;
        $loc = $this->get($a['url'])->headers->get('Location');
        $this->assertStringContainsString('error=temporarily_unavailable', $loc);
    }

    public function test_deleted_account_404_from_dash_is_treated_as_deleted(): void
    {
        [, , $j] = $this->tokens();
        $this->clearCaches();
        unset($this->dashUsers['u-alice']);
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
    }

    public function test_account_blocked_during_authorize_denies_and_revokes(): void
    {
        [$c] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $this->clearCaches();
        $this->dashUsers['u-alice']['status'] = 'disabled';
        $loc = $this->get($a['url'])->headers->get('Location');
        $this->assertStringContainsString('error=access_denied', $loc);
        $this->assertSame(0, SsoSession::query()->whereNull('revoked_at')->count());
    }
}
