<?php

namespace App\Services\Oidc;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

final class AccessTokenEntity implements AccessTokenEntityInterface
{
    use EntityTrait, TokenEntityTrait;

    private string $kid = '';

    private string $pem = '';

    public ?string $sid = null;

    private ?string $jwt = null;

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        // Ueberschrieben: der Schluessel stammt aus dem KeyManager (setSigningKey).
    }

    public function setSigningKey(string $kid, string $pem): void
    {
        $this->kid = $kid;
        $this->pem = $pem;
    }

    public function toString(): string
    {
        if ($this->jwt !== null) {
            return $this->jwt;
        }
        $cfg = Configuration::forAsymmetricSigner(new Sha256, InMemory::plainText($this->pem), InMemory::plainText('empty', 'empty'));
        $now = new DateTimeImmutable;
        $builder = $cfg->builder()
            ->issuedBy(config('vylaris.issuer'))
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withHeader('kid', $this->kid)
            ->withHeader('typ', 'at+jwt')
            ->withClaim('client_id', $this->getClient()->getIdentifier())
            ->withClaim('scope', implode(' ', array_map(fn (ScopeEntityInterface $s) => $s->getIdentifier(), $this->getScopes())));
        if ($this->sid !== null) {
            $builder = $builder->withClaim('sid', SsoSessions::publicSid($this->sid));
        }

        return $this->jwt = $builder->getToken($cfg->signer(), $cfg->signingKey())->toString();
    }
}
