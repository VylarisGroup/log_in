<?php

namespace Tests\Feature;

use App\Models\Setting;
use App\Services\Dash\DashClient;
use App\Services\Dash\DashProtocolException;
use App\Services\Vylaris\Signer;
use Illuminate\Support\Facades\DB;
use Tests\DashTestCase;

class DashApiAuthTest extends DashTestCase
{
    public function test_unsigned_request_is_rejected(): void
    {
        $this->getJson('/api/dash/v1/health')->assertStatus(401);
        $this->getJson('/api/dash/v1/clients')->assertStatus(401);
    }

    public function test_valid_signature_is_accepted_and_response_is_signed_and_nonce_bound(): void
    {
        $r = $this->dashApi('GET', '/api/dash/v1/health')->assertOk()->assertJsonPath('status', 'ok');
        $ts = (int) $r->headers->get('X-Vylaris-Timestamp');
        $sig = $r->headers->get('X-Vylaris-Signature');
        $canon = Signer::responseCanonical(200, $this->lastDashNonce, $ts, $r->getContent());
        $this->assertTrue(Signer::verify($canon, $sig, $this->loginKeys['public']));
        // an eine andere Anfrage-Nonce gebunden -> ungueltig
        $this->assertFalse(Signer::verify(Signer::responseCanonical(200, 'andere-nonce-andere-nonce', $ts, $r->getContent()), $sig, $this->loginKeys['public']));
    }

    public function test_replayed_request_is_rejected(): void
    {
        $nonce = Signer::randomNonce();
        $this->dashApi('GET', '/api/dash/v1/health', null, ['nonce' => $nonce])->assertOk();
        $this->dashApi('GET', '/api/dash/v1/health', null, ['nonce' => $nonce])->assertStatus(401)->assertJsonPath('error', 'replay');
    }

    public function test_wrong_key_wrong_key_id_and_tampering_are_rejected(): void
    {
        $other = Signer::generateKeypair();
        $this->dashApi('GET', '/api/dash/v1/health', null, ['secret' => $other['secret']])->assertStatus(401)->assertJsonPath('error', 'bad_signature');
        $this->dashApi('GET', '/api/dash/v1/health', null, ['key_id' => 'unbekannt'])->assertStatus(401);
        // Body nach dem Signieren veraendert: Signatur ueber anderen Hash
        $ts = time();
        $nonce = Signer::randomNonce();
        $sig = Signer::sign(Signer::requestCanonical('POST', '/api/dash/v1/users/u-alice/revoke', $ts, $nonce, '{"reason":"x"}'), $this->dashKeys['secret']);
        $this->call('POST', '/api/dash/v1/users/u-alice/revoke', [], [], [], [
            'HTTP_X_VYLARIS_KEY_ID' => 'dash-install-0001', 'HTTP_X_VYLARIS_TIMESTAMP' => (string) $ts, 'HTTP_X_VYLARIS_NONCE' => $nonce,
            'HTTP_X_VYLARIS_SIGNATURE' => $sig, 'CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json',
        ], '{"reason":"anderer-inhalt"}')->assertStatus(401);
        // Pfad veraendert
        $sig2 = Signer::sign(Signer::requestCanonical('GET', '/api/dash/v1/health', $ts, Signer::randomNonce(), ''), $this->dashKeys['secret']);
        $this->call('GET', '/api/dash/v1/clients', [], [], [], ['HTTP_X_VYLARIS_KEY_ID' => 'dash-install-0001', 'HTTP_X_VYLARIS_TIMESTAMP' => (string) $ts, 'HTTP_X_VYLARIS_NONCE' => Signer::randomNonce(), 'HTTP_X_VYLARIS_SIGNATURE' => $sig2, 'HTTP_ACCEPT' => 'application/json'])->assertStatus(401);
    }

    public function test_stale_and_future_timestamps_are_rejected(): void
    {
        $this->dashApi('GET', '/api/dash/v1/health', null, ['ts' => time() - 600])->assertStatus(401)->assertJsonPath('error', 'timestamp_out_of_range');
        $this->dashApi('GET', '/api/dash/v1/health', null, ['ts' => time() + 600])->assertStatus(401)->assertJsonPath('error', 'timestamp_out_of_range');
    }

    public function test_api_unavailable_until_dash_is_configured(): void
    {
        DB::table('settings')->where('key', 'dash.public_key')->delete();
        $this->dashApi('GET', '/api/dash/v1/health')->assertStatus(503);
    }

    public function test_dash_client_rejects_unsigned_or_forged_dash_responses(): void
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $this->clearCaches();

        // Antwort mit fremdem Schluessel signiert (MITM) -> keine Freigabe
        $evil = Signer::generateKeypair();
        $this->dashSignSecret = $evil['secret'];
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);

        // Antwort ohne Signatur
        $this->dashSignSecret = null;
        $this->dashUnsigned = true;
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);

        // Gegenprobe: korrekt signiert funktioniert
        $this->dashUnsigned = false;
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertOk();
    }

    public function test_dash_url_must_be_https_in_production_mode(): void
    {
        config(['vylaris.dash.allow_http' => false]);
        Setting::put('dash.base_url', 'http://dash.test');
        $this->expectException(DashProtocolException::class);
        app(DashClient::class)->health();
    }
}
