<?php

namespace Tests\Unit;

use App\Models\Audit;
use App\Services\Vylaris\Signer;
use App\Services\Vylaris\Totp;
use App\Services\Vylaris\UriPolicy;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class CryptoAndPolicyTest extends TestCase
{
    use RefreshDatabase;

    public function test_signer_roundtrip_and_tamper_detection(): void
    {
        $k = Signer::generateKeypair();
        $m = Signer::requestCanonical('POST', '/x', 1000, 'nonce', '{"a":1}');
        $sig = Signer::sign($m, $k['secret']);
        $this->assertTrue(Signer::verify($m, $sig, $k['public']));
        $this->assertFalse(Signer::verify($m.'x', $sig, $k['public']));
        $this->assertFalse(Signer::verify($m, $sig, Signer::generateKeypair()['public']));
        $this->assertFalse(Signer::verify($m, 'kaputt', $k['public']));
        $this->assertFalse(Signer::verify($m, $sig, 'kaputt'));
    }

    public function test_canonical_binds_method_path_timestamp_nonce_and_body(): void
    {
        $base = Signer::requestCanonical('GET', '/a', 1, 'n', '');
        foreach ([['POST', '/a', 1, 'n', ''], ['GET', '/b', 1, 'n', ''], ['GET', '/a', 2, 'n', ''], ['GET', '/a', 1, 'm', ''], ['GET', '/a', 1, 'n', 'x']] as $args) {
            $this->assertNotSame($base, Signer::requestCanonical(...$args));
        }
    }

    public function test_sealed_box_only_opens_for_recipient(): void
    {
        $r = Signer::generateBoxKeypair();
        $s = Signer::seal('geheim', $r['public']);
        $this->assertSame('geheim', Signer::unseal($s, $r['secret'], $r['public']));
        $o = Signer::generateBoxKeypair();
        $this->assertNull(Signer::unseal($s, $o['secret'], $o['public']));
    }

    public function test_totp_rfc6238_vectors(): void
    {
        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
        $this->assertSame('287082', Totp::code($secret, intdiv(59, 30)));
        $this->assertSame('081804', Totp::code($secret, intdiv(1111111109, 30)));
        $this->assertTrue(Totp::verify($secret, '287082', 59));
        $this->assertTrue(Totp::verify($secret, '287082', 59 + 30)); // +-1 Schritt
        $this->assertFalse(Totp::verify($secret, '287082', 59 + 120));
        $this->assertFalse(Totp::verify($secret, 'abcdef', 59));
    }

    public function test_uri_policy(): void
    {
        $this->assertSame([], UriPolicy::validate(['https://app.example.ch/cb', 'https://example.ch/x'], 'example.ch'));
        foreach (['http://example.ch/cb', 'https://evil.ch/cb', 'https://example.ch.evil.ch/cb', 'https://example.ch/cb#a', 'https://*.example.ch/cb', 'ftp://example.ch/', '//example.ch/cb', 'https://example.ch/a b', 'https://u@example.ch/cb'] as $u) {
            $this->assertNotSame([], UriPolicy::validate([$u], 'example.ch'), $u);
        }
        $this->assertNotSame([], UriPolicy::validate([], 'example.ch'));
        $this->assertTrue(UriPolicy::validDomain('tickets.example.ch'));
        $this->assertFalse(UriPolicy::validDomain('exa mple.ch'));
        $this->assertFalse(UriPolicy::validDomain('https://example.ch'));
    }

    public function test_audit_never_stores_secrets(): void
    {
        Audit::log('test', 'a', 'b', ['password' => 'p', 'client_secret' => 's', 'access_token' => 't', 'code' => 'c', 'mfa_code' => '1', 'ok' => 'sichtbar']);
        $row = Audit::query()->first();
        $this->assertSame(['ok' => 'sichtbar'], $row->context);
    }
}
