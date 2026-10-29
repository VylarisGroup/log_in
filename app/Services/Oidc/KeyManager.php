<?php

namespace App\Services\Oidc;

use App\Models\Audit;
use App\Models\SigningKey;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

/**
 * Verwaltung der Token-Signaturschluessel (RS256). Genau ein aktiver Schluessel; nach einer Rotation bleibt der
 * alte Schluessel bis retire_after in der JWKS, damit bereits ausgestellte Tokens pruefbar bleiben.
 */
class KeyManager
{
    public function generate(): SigningKey
    {
        $res = openssl_pkey_new(['private_key_bits' => (int) config('vylaris.keys.rsa_bits'), 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($res === false) {
            throw new \RuntimeException('Schluesselerzeugung fehlgeschlagen');
        }
        openssl_pkey_export($res, $privatePem);
        $public = openssl_pkey_get_details($res)['key'];
        $kid = 'k'.now()->format('Ymd').'-'.Str::lower(Str::random(10));

        return SigningKey::query()->create([
            'kid' => $kid,
            'alg' => 'RS256',
            'public_pem' => $public,
            'private_enc' => Crypt::encryptString($privatePem),
            'status' => 'active',
            'activated_at' => now(),
        ]);
    }

    public function ensureActive(): SigningKey
    {
        return $this->active() ?? $this->generate();
    }

    public function active(): ?SigningKey
    {
        return SigningKey::query()->where('status', 'active')->orderByDesc('activated_at')->first();
    }

    public function rotate(string $actor = 'system'): SigningKey
    {
        $old = $this->active();
        $new = $this->generate();
        if ($old !== null) {
            $old->update([
                'status' => 'retired',
                'retire_after' => now()->addDays((int) config('vylaris.keys.rotation_overlap_days')),
            ]);
        }
        Audit::log('keys.rotated', $actor, $new->kid, ['previous' => $old?->kid]);

        return $new;
    }

    /** Sofortiger Widerruf (Kompromittierung): Schluessel verschwindet aus der JWKS, damit signierte Tokens ungueltig werden. */
    public function revoke(string $kid, string $actor = 'system'): void
    {
        $key = SigningKey::query()->findOrFail($kid);
        $wasActive = $key->status === 'active';
        $key->update(['status' => 'revoked', 'retire_after' => now()]);
        Audit::log('keys.revoked', $actor, $kid);
        if ($wasActive) {
            $this->generate();
        }
    }

    /** Entfernt abgelaufene, zurueckgezogene Schluessel aus der JWKS-Publikation. */
    public function prune(): int
    {
        return SigningKey::query()->where('status', 'retired')->where('retire_after', '<', now())->update(['status' => 'expired']);
    }

    public function privatePem(SigningKey $key): string
    {
        return Crypt::decryptString($key->private_enc);
    }

    /** Schluessel, mit denen Signaturen noch gueltig sind (aktiv + Rotationsfenster). */
    public function verifiable(string $kid): ?SigningKey
    {
        $key = SigningKey::query()->find($kid);
        if ($key === null || ! in_array($key->status, ['active', 'retired'], true)) {
            return null;
        }
        if ($key->status === 'retired' && $key->retire_after !== null && $key->retire_after->isPast()) {
            return null;
        }

        return $key;
    }

    /** @return array{keys: list<array<string, string>>} */
    public function jwks(): array
    {
        $keys = SigningKey::query()
            ->where(fn ($q) => $q->where('status', 'active')->orWhere(fn ($q2) => $q2->where('status', 'retired')->where('retire_after', '>', now())))
            ->get();

        return ['keys' => $keys->map(fn (SigningKey $k) => $this->jwk($k))->all()];
    }

    /** @return array<string, string> */
    private function jwk(SigningKey $k): array
    {
        $d = openssl_pkey_get_details(openssl_pkey_get_public($k->public_pem));

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $k->kid,
            'n' => rtrim(strtr(base64_encode($d['rsa']['n']), '+/', '-_'), '='),
            'e' => rtrim(strtr(base64_encode($d['rsa']['e']), '+/', '-_'), '='),
        ];
    }
}
