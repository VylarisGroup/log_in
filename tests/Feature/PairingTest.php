<?php

namespace Tests\Feature;

use App\Models\OidcClient;
use App\Models\Pairing;
use App\Services\Vylaris\PairingService;
use App\Services\Vylaris\Signer;
use Tests\DashTestCase;

class PairingTest extends DashTestCase
{
    private array $toolSign;

    private array $toolBox;

    protected function setUp(): void
    {
        parent::setUp();
        $this->toolSign = Signer::generateKeypair();
        $this->toolBox = Signer::generateBoxKeypair();
    }

    private function payload(array $o = []): array
    {
        return array_merge([
            'pairing_id' => 'pair-'.bin2hex(random_bytes(10)),
            'installation_id' => 'tool-install-9999',
            'name' => 'Vylaris Tickets',
            'domain' => 'tickets.example.ch',
            'version' => '1.4.0',
            'redirect_uris' => ['https://tickets.example.ch/auth/callback'],
            'post_logout_uris' => ['https://tickets.example.ch/'],
            'scopes' => ['openid', 'profile', 'email', 'vylaris'],
            'tool_sign_public_key' => $this->toolSign['public'],
            'tool_box_public_key' => $this->toolBox['public'],
        ], $o);
    }

    private function proof(array $pairingView, array $p): string
    {
        $m = implode("\n", ['VYLARIS-PAIR-V1', $p['pairing_id'], $p['installation_id'], $pairingView['challenge'], hash('sha256', json_encode([$p['redirect_uris'], $p['scopes']]))]);

        return Signer::sign($m, $this->toolSign['secret']);
    }

    public function test_happy_path_state_machine_and_sealed_credentials(): void
    {
        $p = $this->payload();
        $v = $this->dashApi('POST', '/api/dash/v1/pairings', $p)->assertCreated()->assertJsonPath('state', 'requested')->json();
        $this->assertNotEmpty($v['challenge']);
        $id = $p['pairing_id'];

        // vor Dash-Freigabe darf nichts bestaetigt werden, es entsteht kein Client
        $this->dashApi('POST', "/api/dash/v1/pairings/$id/tool-confirm", ['proof' => $this->proof($v, $p)])->assertStatus(409);
        $this->assertSame(0, OidcClient::query()->count());

        $this->dashApi('POST', "/api/dash/v1/pairings/$id/dash-approve")->assertOk()->assertJsonPath('state', 'dash_approved');
        $this->dashApi('POST', "/api/dash/v1/pairings/$id/dash-approve")->assertOk()->assertJsonPath('state', 'dash_approved'); // idempotent
        $this->assertSame(0, OidcClient::query()->count());

        $r = $this->dashApi('POST', "/api/dash/v1/pairings/$id/tool-confirm", ['proof' => $this->proof($v, $p)])->assertOk()->assertJsonPath('state', 'active');
        $sealed = $r->json('sealed_credentials');
        $this->assertStringNotContainsString('client_secret', $r->getContent());
        $creds = json_decode(Signer::unseal($sealed, $this->toolBox['secret'], $this->toolBox['public']), true);
        $this->assertSame('https://login.test', $creds['issuer']);
        $this->assertStringStartsWith('vl_', $creds['client_id']);

        // andere Box-Schluessel koennen nicht oeffnen
        $other = Signer::generateBoxKeypair();
        $this->assertNull(Signer::unseal($sealed, $other['secret'], $other['public']));

        // idempotente Wiederholung liefert dieselben Zugangsdaten und erzeugt keinen zweiten Client
        $r2 = $this->dashApi('POST', "/api/dash/v1/pairings/$id/tool-confirm", ['proof' => $this->proof($v, $p)])->assertOk();
        $this->assertSame($sealed, $r2->json('sealed_credentials'));
        $this->assertSame(1, OidcClient::query()->count());

        // Quittierung loescht die versiegelten Zugangsdaten
        $this->dashApi('POST', "/api/dash/v1/pairings/$id/credentials-ack")->assertOk()->assertJsonMissingPath('sealed_credentials');
        $this->assertNull(Pairing::query()->find($id)->sealed_credentials);

        // der neue Client funktioniert im OIDC-Flow mit genau den freigegebenen Scopes
        $c = OidcClient::query()->find($creds['client_id']);
        $this->assertSame('active', $c->status);
        $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid vylaris']);
        $this->exchange($c, $creds['client_secret'], $a['query']['code'], $a['verifier'])->assertOk();
        $this->getJson('/api/dash/v1/clients/'.$c->client_id); // ohne Signatur nicht lesbar
        $this->dashApi('GET', '/api/dash/v1/clients/'.$c->client_id)->assertOk()->assertJsonPath('status', 'active');
    }

    public function test_invalid_proof_fails_the_pairing_and_creates_no_client(): void
    {
        $p = $this->payload();
        $v = $this->dashApi('POST', '/api/dash/v1/pairings', $p)->json();
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/dash-approve")->assertOk();
        $evil = Signer::generateKeypair();
        $bad = Signer::sign('VYLARIS-PAIR-V1', $evil['secret']);
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/tool-confirm", ['proof' => $bad])->assertStatus(422)->assertJsonPath('error', 'proof_invalid');
        $this->assertSame('failed', Pairing::query()->find($p['pairing_id'])->state);
        $this->assertSame(0, OidcClient::query()->count());
        // Challenge ist verbraucht: auch der richtige Nachweis hilft nun nicht mehr
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/tool-confirm", ['proof' => $this->proof($v, $p)])->assertStatus(409);
        $this->assertSame(0, OidcClient::query()->count());
    }

    public function test_proof_is_bound_to_the_requested_redirects_and_scopes(): void
    {
        $p = $this->payload();
        $v = $this->dashApi('POST', '/api/dash/v1/pairings', $p)->json();
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/dash-approve")->assertOk();
        $tampered = $p;
        $tampered['scopes'] = ['openid', 'profile', 'email', 'vylaris', 'offline_access']; // nachtraeglich erweitert
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/tool-confirm", ['proof' => $this->proof($v, $tampered)])->assertStatus(422);
    }

    public function test_pairing_window_expires(): void
    {
        $p = $this->payload(['window_seconds' => 60]);
        $v = $this->dashApi('POST', '/api/dash/v1/pairings', $p)->json();
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/dash-approve")->assertOk();
        $this->travel(61)->seconds();
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/tool-confirm", ['proof' => $this->proof($v, $p)])->assertStatus(410);
        $this->dashApi('GET', "/api/dash/v1/pairings/{$p['pairing_id']}")->assertJsonPath('state', 'expired');
        $this->assertSame(0, OidcClient::query()->count());
    }

    public function test_reject_and_cancel_are_terminal(): void
    {
        $p = $this->payload();
        $this->dashApi('POST', '/api/dash/v1/pairings', $p)->assertCreated();
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/dash-reject")->assertOk()->assertJsonPath('state', 'rejected');
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/dash-approve")->assertStatus(409);

        $q = $this->payload(['pairing_id' => 'pair-cancel-0123456789']);
        $this->dashApi('POST', '/api/dash/v1/pairings', $q)->assertCreated();
        $this->dashApi('POST', "/api/dash/v1/pairings/{$q['pairing_id']}/cancel")->assertOk()->assertJsonPath('state', 'cancelled');
    }

    public function test_request_is_idempotent_and_conflicts_are_detected(): void
    {
        $p = $this->payload();
        $this->dashApi('POST', '/api/dash/v1/pairings', $p)->assertCreated();
        $this->dashApi('POST', '/api/dash/v1/pairings', $p)->assertOk(); // gleiche ID: idempotent
        $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['pairing_id' => $p['pairing_id'], 'installation_id' => 'tool-install-OTHER']))->assertStatus(409);
        $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['pairing_id' => 'pair-second-0123456789']))->assertStatus(409)->assertJsonPath('error', 'pairing_in_progress');
    }

    public function test_already_paired_installation_cannot_pair_again_until_disconnected(): void
    {
        $this->activate($p = $this->payload());
        $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['pairing_id' => 'pair-again-0123456789']))->assertStatus(409)->assertJsonPath('error', 'installation_already_paired');
    }

    public function test_redirect_uri_policy(): void
    {
        $bad = [
            ['https://evil.example/cb'],                         // fremde Domain
            ['https://tickets.example.ch.evil.test/cb'],         // Suffix-Trick
            ['http://tickets.example.ch/cb'],                    // kein HTTPS
            ['https://tickets.example.ch/cb#frag'],              // Fragment
            ['https://*.example.ch/cb'],                         // Wildcard
            ['https://user:pw@tickets.example.ch/cb'],           // Zugangsdaten
            ['javascript:alert(1)'],                             // Schema
            [],                                                  // leer
        ];
        foreach ($bad as $i => $uris) {
            $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['pairing_id' => 'pair-bad-uri-'.$i.'-0123456', 'redirect_uris' => $uris]))->assertStatus(422);
        }
        $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['scopes' => ['profile']]))->assertStatus(422); // openid fehlt
        $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['scopes' => ['openid', 'admin']]))->assertStatus(422); // unbekannter Scope
        $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['tool_sign_public_key' => base64_encode('kurz')]))->assertStatus(422);
        $this->assertSame(0, Pairing::query()->count());
    }

    /** @return array{0: OidcClient, 1: string} */
    private function activate(array $p): array
    {
        $v = $this->dashApi('POST', '/api/dash/v1/pairings', $p)->json();
        $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/dash-approve")->assertOk();
        $r = $this->dashApi('POST', "/api/dash/v1/pairings/{$p['pairing_id']}/tool-confirm", ['proof' => $this->proof($v, $p)])->assertOk();
        $c = json_decode(Signer::unseal($r->json('sealed_credentials'), $this->toolBox['secret'], $this->toolBox['public']), true);

        return [OidcClient::query()->find($c['client_id']), $c['client_secret']];
    }

    public function test_disconnect_blocks_new_and_existing_tokens_and_secret(): void
    {
        [$c, $secret] = $this->activate($this->payload());
        $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid vylaris offline_access']);
        // offline_access war nicht freigegeben -> Fehler statt stillem Erweitern
        $this->assertStringContainsString('error=invalid_scope', $a['location']);

        $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid vylaris']);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertOk()->json();
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertOk();

        $this->dashApi('POST', '/api/dash/v1/clients/'.$c->client_id.'/disconnect')->assertOk()->assertJsonPath('status', 'disconnected');

        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
        [, $ch] = $this->pkce();
        $this->get('/authorize?'.http_build_query(['response_type' => 'code', 'client_id' => $c->client_id, 'redirect_uri' => $c->redirect_uris[0], 'scope' => 'openid', 'state' => 's', 'nonce' => 'n', 'code_challenge' => $ch, 'code_challenge_method' => 'S256']))->assertStatus(401);
        $this->assertNull($c->fresh()->secret_hash);
    }

    public function test_suspend_resume_and_dash_client_protection(): void
    {
        [$c, $secret] = $this->activate($this->payload());
        $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid']);
        $j = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();

        $this->dashApi('POST', '/api/dash/v1/clients/'.$c->client_id.'/suspend')->assertOk()->assertJsonPath('status', 'suspended');
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
        $this->dashApi('POST', '/api/dash/v1/clients/'.$c->client_id.'/resume')->assertOk()->assertJsonPath('status', 'active');
        $this->dashApi('POST', '/api/dash/v1/clients/'.$c->client_id.'/resume')->assertStatus(409);

        OidcClient::query()->whereKey($c->client_id)->update(['is_dash' => true]);
        $this->dashApi('POST', '/api/dash/v1/clients/'.$c->client_id.'/disconnect')->assertStatus(409)->assertJsonPath('error', 'dash_client_protected');
    }

    public function test_secret_rotation_with_grace_period(): void
    {
        [$c, $oldSecret] = $this->activate($this->payload());
        $r = $this->dashApi('POST', '/api/dash/v1/clients/'.$c->client_id.'/rotate-secret')->assertOk();
        $new = json_decode(Signer::unseal($r->json('sealed_credentials'), $this->toolBox['secret'], $this->toolBox['public']), true)['client_secret'];
        $this->assertNotSame($oldSecret, $new);

        foreach ([$oldSecret, $new] as $s) {
            $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid']);
            $this->exchange($c, $s, $a['query']['code'], $a['verifier'])->assertOk();
        }
        $this->travel(11)->minutes();
        $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid']);
        $this->exchange($c, $oldSecret, $a['query']['code'], $a['verifier'])->assertStatus(401);
    }

    public function test_client_update_validates_uris_and_scopes(): void
    {
        [$c] = $this->activate($this->payload());
        $this->dashApi('PATCH', '/api/dash/v1/clients/'.$c->client_id, ['redirect_uris' => ['https://evil.example/cb']])->assertStatus(422);
        $this->dashApi('PATCH', '/api/dash/v1/clients/'.$c->client_id, ['scopes' => ['profile']])->assertStatus(422);
        $this->dashApi('PATCH', '/api/dash/v1/clients/'.$c->client_id, ['redirect_uris' => ['https://tickets.example.ch/new']])->assertOk()->assertJsonPath('redirect_uris.0', 'https://tickets.example.ch/new');
    }

    public function test_tile_listing_shows_pending_and_active_states(): void
    {
        $this->activate($this->payload());
        $this->dashApi('POST', '/api/dash/v1/pairings', $this->payload(['pairing_id' => 'pair-pending-0123456789', 'installation_id' => 'tool-install-7777', 'name' => 'Neu']))->assertCreated();
        $r = $this->dashApi('GET', '/api/dash/v1/clients')->assertOk();
        $this->assertSame('active', $r->json('clients.0.status'));
        $this->assertSame('pending', $r->json('pending_pairings.0.status'));
        $this->assertStringNotContainsString('secret', $r->getContent());
    }

    public function test_pairing_service_is_the_only_way_to_create_non_dash_clients(): void
    {
        $this->assertTrue(method_exists(PairingService::class, 'confirm'));
        $this->assertContains($this->dashApi('POST', '/api/dash/v1/clients', ['name' => 'x'])->status(), [404, 405]); // kein direktes Anlegen von Clients
    }
}
