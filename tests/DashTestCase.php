<?php

namespace Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Support\FakeDash;

abstract class DashTestCase extends TestCase
{
    use FakeDash, RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->bootFakeDash();
        config(['vylaris.keys.rsa_bits' => 2048]); // schnellere Testschluessel
    }

    /** Dekodiert ein JWT ohne Pruefung (nur zum Lesen von Claims in Tests). */
    protected function jwtParts(string $jwt): array
    {
        [$h, $p] = explode('.', $jwt);
        $d = fn (string $s) => json_decode(base64_decode(strtr($s, '-_', '+/')), true);

        return [$d($h), $d($p)];
    }
}
