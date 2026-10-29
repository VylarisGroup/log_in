<?php

namespace Tests\Feature;

use App\Models\SigningKey;
use App\Services\Oidc\KeyManager;
use Tests\DashTestCase;

class KeyRotationTest extends DashTestCase
{
    private function login(): array
    {
        [$c, $secret] = $this->makeClient();
        $a = $this->loginAndAuthorize($c);

        return [$c, $secret, $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->assertOk()->json()];
    }

    public function test_rotation_keeps_old_tokens_valid_during_overlap_and_new_tokens_use_new_key(): void
    {
        [$c, $secret, $old] = $this->login();
        [$h1] = $this->jwtParts($old['access_token']);

        $r = $this->dashApi('POST', '/api/dash/v1/keys/rotate')->assertCreated();
        $newKid = $r->json('kid');
        $this->assertNotSame($h1['kid'], $newKid);

        $kids = array_column($this->getJson('/.well-known/jwks.json')->json('keys'), 'kid');
        $this->assertEqualsCanonicalizing([$h1['kid'], $newKid], $kids);
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$old['access_token']])->assertOk();

        $a = $this->loginAndAuthorize($c);
        $new = $this->exchange($c, $secret, $a['query']['code'], $a['verifier'])->json();
        $this->assertSame($newKid, $this->jwtParts($new['access_token'])[0]['kid']);
        $this->assertSame($newKid, $this->jwtParts($new['id_token'])[0]['kid']);
    }

    public function test_retired_key_disappears_after_overlap_period(): void
    {
        [, , $old] = $this->login();
        $this->dashApi('POST', '/api/dash/v1/keys/rotate')->assertCreated();
        $this->travel(config('vylaris.keys.rotation_overlap_days') + 1)->days();
        $this->assertCount(1, $this->getJson('/.well-known/jwks.json')->json('keys'));
        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$old['access_token']])->assertStatus(401);
    }

    public function test_revoking_a_compromised_key_invalidates_its_tokens_immediately(): void
    {
        [, , $j] = $this->login();
        $kid = $this->jwtParts($j['access_token'])[0]['kid'];
        $this->dashApi('POST', "/api/dash/v1/keys/$kid/revoke")->assertOk()->assertJsonPath('status', 'revoked');

        $this->getJson('/userinfo', ['Authorization' => 'Bearer '.$j['access_token']])->assertStatus(401);
        $keys = $this->getJson('/.well-known/jwks.json')->json('keys');
        $this->assertNotContains($kid, array_column($keys, 'kid'));
        $this->assertCount(1, $keys); // ein neuer aktiver Schluessel wurde erzeugt
    }

    public function test_private_keys_are_encrypted_at_rest_and_never_exposed(): void
    {
        app(KeyManager::class)->ensureActive();
        $row = SigningKey::query()->first();
        $this->assertStringNotContainsString('PRIVATE KEY', $row->getRawOriginal('private_enc'));
        $this->assertArrayNotHasKey('private_enc', $row->toArray());
        $this->assertStringNotContainsString('PRIVATE', $this->getJson('/.well-known/jwks.json')->getContent());
        $list = $this->dashApi('GET', '/api/dash/v1/keys')->assertOk();
        $this->assertStringNotContainsString('PRIVATE', $list->getContent());
        $this->assertStringNotContainsString('private_enc', $list->getContent());
    }

    public function test_exactly_one_active_key(): void
    {
        $km = app(KeyManager::class);
        $km->ensureActive();
        $km->rotate();
        $km->rotate();
        $this->assertSame(1, SigningKey::query()->where('status', 'active')->count());
    }
}
