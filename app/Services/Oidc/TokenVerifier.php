<?php

namespace App\Services\Oidc;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;

/** Prueft von log_in selbst ausgestellte JWTs: Schluessel via kid, Signatur, Issuer, optional Ablauf. */
class TokenVerifier
{
    public function __construct(private readonly KeyManager $keys) {}

    /** @return UnencryptedToken|null null bei jedem Fehler (kein Informationsleck) */
    public function verify(string $jwt, bool $checkExpiry = true): ?UnencryptedToken
    {
        try {
            $token = (new Parser(new JoseEncoder))->parse($jwt);
            if (! $token instanceof Plain) {
                return null;
            }
            if (($token->headers()->get('alg') ?? null) !== 'RS256') {
                return null; // kein "none", keine Algorithmus-Verwechslung
            }
            $kid = $token->headers()->get('kid');
            $key = is_string($kid) ? $this->keys->verifiable($kid) : null;
            if ($key === null) {
                return null;
            }
            $ok = (new Validator)->validate($token, new SignedWith(new Sha256, InMemory::plainText($key->public_pem)), new IssuedBy(config('vylaris.issuer')));
            if (! $ok) {
                return null;
            }
            $now = new DateTimeImmutable;
            if ($checkExpiry && ($token->isExpired($now) || ! $token->hasBeenIssuedBefore($now->modify('+60 seconds')))) {
                return null;
            }

            return $token;
        } catch (\Throwable) {
            return null;
        }
    }
}
