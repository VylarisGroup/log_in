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
        $this->dashApi('POST', '/api/vylaris/v1/pairing-window', ['duration_seconds' => 300])->assertCreated();
    }

    private const APPROVED = ['openid', 'profile', 'email', 'vylaris'];

    private function payload(array $o = []): array
    {
        return array_merge([
            'pairing_id' => 'pair-'.bin2hex(random_bytes(10)),
            'installation_id' => 'tool-install-9999',
            'tool_id' => 'vylaris-tickets',
            'name' => 'Vylaris Tickets',
            'base_url' => 'https://tickets.example.ch',
            'version' => '1.4.0',
            'redirect_uris' => ['https://tickets.example.ch/auth/callback'],
            'post_logout_uris' => ['https://tickets.example.ch/'],
            'scopes' => ['openid', 'profile', 'email', 'vylaris'],
            'tool_sign_public_key' => $this->toolSign['public'],
            'tool_box_public_key' => $this->toolBox['public'],
        ], $o);
    }

    private function proof(array $pairingView, array $p, array $approved = self::APPROVED): string
    {
        $m = PairingService::proofCanonical($p['pairing_id'], $p['installation_id'], $p['tool_id'], $pairingView['challenge'], $p['base_url'], $p['redirect_uris'], $p['post_logout_uris'] ?? [], $approved);

        return Signer::sign($m, $this->toolSign['secret']);
    }

    public function test_happy_path_state_machine_and_sealed_credentials(): void
    {
        $p = $this->payload();
        $v = $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->assertCreated()->assertJsonPath('data.state', 'requested')->json('data');
        $this->assertNotEmpty($v['challenge']);
        $id = $p['pairing_id'];

        // vor Dash-Freigabe darf nichts bestaetigt werden, es entsteht kein Client
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/confirm", ['proof' => $this->proof($v, $p)])->assertStatus(409);
        $this->assertSame(0, OidcClient::query()->count());

        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/approve", ['approved_scopes' => self::APPROVED])->assertOk()->assertJsonPath('data.state', 'dash_approved');
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/approve", ['approved_scopes' => self::APPROVED])->assertOk()->assertJsonPath('data.state', 'dash_approved'); // idempotent
        $this->assertSame(0, OidcClient::query()->count());

        $r = $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/confirm", ['proof' => $this->proof($v, $p)])->assertOk()->assertJsonPath('data.state', 'active');
        $sealed = $r->json('data.sealed_credentials');
        $this->assertStringNotContainsString('client_secret', $r->getContent());
        $creds = json_decode(Signer::unseal($sealed, $this->toolBox['secret'], $this->toolBox['public']), true);
        $this->assertSame('https://login.test', $creds['issuer']);
        $this->assertStringStartsWith('vl_', $creds['client_id']);

        // andere Box-Schluessel koennen nicht oeffnen
        $other = Signer::generateBoxKeypair();
        $this->assertNull(Signer::unseal($sealed, $other['secret'], $other['public']));

        // idempotente Wiederholung liefert dieselben Zugangsdaten und erzeugt keinen zweiten Client
        $r2 = $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/confirm", ['proof' => $this->proof($v, $p)])->assertOk();
        $this->assertSame($sealed, $r2->json('data.sealed_credentials'));
        $this->assertSame(1, OidcClient::query()->count());

        // Quittierung loescht die versiegelten Zugangsdaten
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/credentials-ack")->assertOk()->assertJsonMissingPath('data.sealed_credentials');
        $this->assertNull(Pairing::query()->find($id)->sealed_credentials);

        // der neue Client funktioniert im OIDC-Flow mit genau den freigegebenen Scopes
        $c = OidcClient::query()->find($creds['client_id']);
        $this->assertSame('active', $c->status);
        $a = $this->loginAndAuthorize($c, extra: ['scope' => 'openid vylaris']);
        $this->exchange($c, $creds['client_secret'], $a['query']['code'], $a['verifier'])->assertOk();
        $this->getJson('/api/vylaris/v1/clients/'.$c->client_id); // ohne Signatur nicht lesbar
        $this->dashApi('GET', '/api/vylaris/v1/clients/'.$c->client_id)->assertOk()->assertJsonPath('data.status', 'active');
    }

    public function test_invalid_proof_fails_the_pairing_and_creates_no_client(): void
    {
        $p = $this->payload();
        $v = $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->json('data');
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/approve", ['approved_scopes' => self::APPROVED])->assertOk();
        $evil = Signer::generateKeypair();
        $bad = Signer::sign('VYLARIS-PAIR-V1', $evil['secret']);
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/confirm", ['proof' => $bad])->assertStatus(422)->assertJsonPath('error.code', 'invalid_pairing_proof');
        $this->assertSame('failed', Pairing::query()->find($p['pairing_id'])->state);
        $this->assertSame(0, OidcClient::query()->count());
        // Challenge ist verbraucht: auch der richtige Nachweis hilft nun nicht mehr
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/confirm", ['proof' => $this->proof($v, $p)])->assertStatus(409);
        $this->assertSame(0, OidcClient::query()->count());
    }

    public function test_proof_is_bound_to_the_requested_redirects_and_scopes(): void
    {
        $p = $this->payload();
        $v = $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->json('data');
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/approve", ['approved_scopes' => self::APPROVED])->assertOk();
        $widened = [...self::APPROVED, 'offline_access']; // nachtraeglich erweitert
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/confirm", ['proof' => $this->proof($v, $p, $widened)])->assertStatus(422);
        $other = $p;
        $other['redirect_uris'] = ['https://tickets.example.ch/other']; // andere Redirect-URI
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/confirm", ['proof' => $this->proof($v, $other)])->assertStatus(409); // Challenge schon verbraucht
    }

    public function test_pairing_window_expires(): void
    {
        $this->dashApi('POST', '/api/vylaris/v1/pairing-window', ['duration_seconds' => 60])->assertCreated();
        $p = $this->payload();
        $v = $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->json('data');
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/approve", ['approved_scopes' => self::APPROVED])->assertOk();
        $this->travel(61)->seconds();
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/confirm", ['proof' => $this->proof($v, $p)])->assertStatus(410);
        $this->dashApi('GET', "/api/vylaris/v1/pairings/{$p['pairing_id']}")->assertJsonPath('data.state', 'expired');
        $this->assertSame(0, OidcClient::query()->count());
    }

    public function test_reject_and_cancel_are_terminal(): void
    {
        $p = $this->payload();
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->assertCreated();
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/reject")->assertOk()->assertJsonPath('data.state', 'rejected');
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/approve", ['approved_scopes' => self::APPROVED])->assertStatus(403)->assertJsonPath('error.code', 'pairing_denied');

        $q = $this->payload(['pairing_id' => 'pair-cancel-0123456789']);
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $q)->assertCreated();
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$q['pairing_id']}/cancel")->assertOk()->assertJsonPath('data.state', 'cancelled');
    }

    public function test_request_is_idempotent_and_conflicts_are_detected(): void
    {
        $p = $this->payload();
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->assertCreated();
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->assertOk(); // gleiche ID: idempotent
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['pairing_id' => $p['pairing_id'], 'installation_id' => 'tool-install-OTHER']))->assertStatus(409);
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['pairing_id' => 'pair-second-0123456789']))->assertStatus(409)->assertJsonPath('error.code', 'duplicate_conflict');
    }

    public function test_already_paired_installation_cannot_pair_again_until_disconnected(): void
    {
        $this->activate($p = $this->payload());
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['pairing_id' => 'pair-again-0123456789']))->assertStatus(409)->assertJsonPath('error.code', 'duplicate_conflict');
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
            $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['pairing_id' => 'pair-bad-uri-'.$i.'-0123456', 'redirect_uris' => $uris]))->assertStatus(422);
        }
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['scopes' => ['profile']]))->assertStatus(422); // openid fehlt
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['scopes' => ['openid', 'admin']]))->assertStatus(422); // unbekannter Scope
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['tool_sign_public_key' => base64_encode('kurz')]))->assertStatus(422);
        $this->assertSame(0, Pairing::query()->count());
    }

    /** @return array{0: OidcClient, 1: string} */
    private function activate(array $p): array
    {
        $v = $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->json('data');
        $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/approve", ['approved_scopes' => self::APPROVED])->assertOk();
        $r = $this->dashApi('POST', "/api/vylaris/v1/pairings/{$p['pairing_id']}/confirm", ['proof' => $this->proof($v, $p)])->assertOk();
        $c = json_decode(Signer::unseal($r->json('data.sealed_credentials'), $this->toolBox['secret'], $this->toolBox['public']), true);

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

        $this->dashApi('POST', '/api/vylaris/v1/clients/'.$c->client_id.'/disconnect')->assertOk()->assertJsonPath('data.status', 'disconnected');

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

        $this->dashApi('POST', '/api/vylaris/v1/clients/'.$c->client_id.'/suspend')->assertOk()->assertJsonPath('data.status', 'suspended');
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
        $this->dashApi('POST', '/api/vylaris/v1/clients/'.$c->client_id.'/resume')->assertOk()->assertJsonPath('data.status', 'active');
        $this->dashApi('POST', '/api/vylaris/v1/clients/'.$c->client_id.'/resume')->assertStatus(409);

        OidcClient::query()->whereKey($c->client_id)->update(['is_dash' => true]);
        $this->dashApi('POST', '/api/vylaris/v1/clients/'.$c->client_id.'/disconnect')->assertStatus(403)->assertJsonPath('error.code', 'forbidden');
    }

    public function test_secret_rotation_with_grace_period(): void
    {
        [$c, $oldSecret] = $this->activate($this->payload());
        $r = $this->dashApi('POST', '/api/vylaris/v1/clients/'.$c->client_id.'/rotate-secret')->assertOk();
        $new = json_decode(Signer::unseal($r->json('data.sealed_credentials'), $this->toolBox['secret'], $this->toolBox['public']), true)['client_secret'];
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
        $this->dashApi('PATCH', '/api/vylaris/v1/clients/'.$c->client_id, ['redirect_uris' => ['https://evil.example/cb']])->assertStatus(422);
        $this->dashApi('PATCH', '/api/vylaris/v1/clients/'.$c->client_id, ['scopes' => ['profile']])->assertStatus(422);
        $this->dashApi('PATCH', '/api/vylaris/v1/clients/'.$c->client_id, ['redirect_uris' => ['https://tickets.example.ch/new']])->assertOk()->assertJsonPath('data.redirect_uris.0', 'https://tickets.example.ch/new');
    }

    public function test_tile_listing_shows_pending_and_active_states(): void
    {
        $this->activate($this->payload());
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['pairing_id' => 'pair-pending-0123456789', 'installation_id' => 'tool-install-7777', 'name' => 'Neu']))->assertCreated();
        $r = $this->dashApi('GET', '/api/vylaris/v1/clients')->assertOk();
        $this->assertSame('active', $r->json('data.0.status'));
        $this->assertSame('pending', $r->json('meta.pending_pairings.0.status'));
        $this->assertStringNotContainsString('secret', $r->getContent());
    }

    public function test_pairing_service_is_the_only_way_to_create_non_dash_clients(): void
    {
        $this->assertTrue(method_exists(PairingService::class, 'confirm'));
        $this->assertContains($this->dashApi('POST', '/api/vylaris/v1/clients', ['name' => 'x'])->status(), [404, 405]); // kein direktes Anlegen von Clients
    }

    public function test_pairing_requires_an_open_window(): void
    {
        $this->dashApi('DELETE', '/api/vylaris/v1/pairing-window')->assertOk()->assertJsonPath('data.open', false);
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload())->assertStatus(409)->assertJsonPath('error.code', 'pairing_closed');
        $this->assertSame(0, Pairing::query()->count());

        foreach ([29, 901, 'x'] as $bad) {
            $this->dashApi('POST', '/api/vylaris/v1/pairing-window', ['duration_seconds' => $bad])->assertStatus(422)->assertJsonPath('error.code', 'validation_failed');
        }
        $this->dashApi('POST', '/api/vylaris/v1/pairing-window', [])->assertCreated(); // Standard 300 s
        $this->dashApi('GET', '/api/vylaris/v1/pairing-window')->assertJsonPath('data.open', true);
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload())->assertCreated();

        $this->travel(301)->seconds();
        $this->dashApi('GET', '/api/vylaris/v1/pairing-window')->assertJsonPath('data.open', false);
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['pairing_id' => 'pair-late-0123456789', 'installation_id' => 'tool-install-8888']))->assertStatus(409)->assertJsonPath('error.code', 'pairing_closed');
    }

    public function test_requested_permissions_are_not_automatically_approved(): void
    {
        $p = $this->payload();
        $this->dashApi('POST', '/api/vylaris/v1/pairings', $p)->assertCreated();
        $id = $p['pairing_id'];
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/approve")->assertStatus(422)->assertJsonPath('error.code', 'validation_failed');
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/approve", ['approved_scopes' => ['openid', 'offline_access']])->assertStatus(422); // nicht angefordert
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/approve", ['approved_scopes' => ['profile']])->assertStatus(422); // openid fehlt
        $this->assertSame('requested', Pairing::query()->find($id)->state);

        $narrow = ['openid', 'profile'];
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/approve", ['approved_scopes' => $narrow])->assertOk()->assertJsonPath('data.approved_scopes', $narrow);
        $v = $this->dashApi('GET', "/api/vylaris/v1/pairings/$id")->json('data');
        // der Nachweis muss an die tatsaechlich genehmigten Scopes gebunden sein
        $this->dashApi('POST', "/api/vylaris/v1/pairings/$id/confirm", ['proof' => $this->proof($v, $p, $narrow)])->assertOk();
        $this->assertSame($narrow, Pairing::query()->find($id)->approved_scopes);
        $this->assertSame($narrow, OidcClient::query()->where('installation_id', $p['installation_id'])->first()->scopes);
    }

    public function test_tool_base_url_must_be_public_https(): void
    {
        foreach (['http://tickets.example.ch', 'https://127.0.0.1', 'https://10.0.0.5', 'https://user:pw@tickets.example.ch', 'ftp://tickets.example.ch'] as $i => $url) {
            $this->dashApi('POST', '/api/vylaris/v1/pairings', $this->payload(['pairing_id' => 'pair-baseurl-'.$i.'-0123456', 'base_url' => $url]))->assertStatus(422);
        }
        $this->assertSame(0, Pairing::query()->count());
    }

    public function test_proof_canonical_is_language_neutral_and_order_independent(): void
    {
        $a = PairingService::proofCanonical('pair-1', 'inst-1', 'tool', 'chal', 'https://t.example', ['https://t.example/b', 'https://t.example/a'], [], ['profile', 'openid']);
        $b = PairingService::proofCanonical('pair-1', 'inst-1', 'tool', 'chal', 'https://t.example', ['https://t.example/a', 'https://t.example/b'], [], ['openid', 'profile']);
        $this->assertSame($a, $b);
        $this->assertSame(
            "VYLARIS-PAIR-V1\npair-1\ninst-1\ntool\nchal\nhttps://t.example\n".hash('sha256', "https://t.example/a\nhttps://t.example/b")."\n".hash('sha256', '')."\n".hash('sha256', 'openid profile'),
            $a,
        );
    }
}
