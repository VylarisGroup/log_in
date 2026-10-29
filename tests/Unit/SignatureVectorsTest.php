<?php

namespace Tests\Unit;

use App\Services\Vylaris\PairingService;
use App\Services\Vylaris\Signer;
use PHPUnit\Framework\TestCase;

/** Gemeinsame Testvektoren (docs/test-vectors.json) - identisch in allen Vylaris-Projekten. */
class SignatureVectorsTest extends TestCase
{
    public function test_all_shared_vectors_are_reproduced_exactly(): void
    {
        $file = json_decode((string) file_get_contents(__DIR__.'/../../docs/test-vectors.json'), true);
        $pub = $file['key']['public_key'];
        $sec = $file['key']['secret_key'];
        $this->assertSame(32, strlen(base64_decode($pub)));
        $count = 0;
        foreach ($file['vectors'] as $v) {
            $canon = match ($v['type']) {
                'request' => Signer::requestCanonical($v['method'], $v['path'], $v['ts'], $v['nonce'], $v['body']),
                'response' => Signer::responseCanonical($v['status'], $v['request_nonce'], $v['ts'], $v['body']),
                'pairing_proof' => PairingService::proofCanonical($v['pairing_id'], $v['installation_id'], $v['tool_id'], $v['challenge'], $v['base_url'], $v['redirect_uris'], $v['post_logout_uris'], $v['approved_scopes']),
            };
            $this->assertSame($v['canonical'], $canon, $v['name'].': kanonische Zeichenkette');
            $this->assertSame($v['signature'], Signer::sign($canon, $sec), $v['name'].': Signatur (Ed25519 ist deterministisch)');
            $this->assertTrue(Signer::verify($canon, $v['signature'], $pub), $v['name'].': Verifikation');
            $this->assertFalse(Signer::verify($canon.'x', $v['signature'], $pub), $v['name'].': Manipulation wird erkannt');
            if (isset($v['body'])) {
                $this->assertSame($v['body_sha256'], hash('sha256', $v['body']));
            }
            $count++;
        }
        $this->assertSame(4, $count);
    }

    public function test_canonical_format_has_no_trailing_newline_and_empty_body_hash(): void
    {
        $c = Signer::requestCanonical('get', '/x', 1, 'n', '');
        $this->assertSame("VYLARIS-V1\nGET\n/x\n1\nn\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", $c);
    }
}
