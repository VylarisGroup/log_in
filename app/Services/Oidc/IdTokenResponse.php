<?php

namespace App\Services\Oidc;

use App\Services\Dash\DashClient;
use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

/** Ergaenzt die Token-Antwort um das ID-Token (OIDC Core 3.1.3.3). */
class IdTokenResponse extends BearerTokenResponse
{
    public function __construct(
        private readonly KeyManager $keys,
        private readonly DashClient $dash,
        private readonly OidcContext $ctx,
    ) {}

    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        $scopes = array_map(fn ($s) => $s->getIdentifier(), $accessToken->getScopes());
        if (! $this->ctx->issueIdToken || ! in_array('openid', $scopes, true)) {
            return [];
        }

        return ['id_token' => $this->buildIdToken($accessToken, $scopes)];
    }

    /** @param  list<string>  $scopes */
    private function buildIdToken(AccessTokenEntityInterface $at, array $scopes): string
    {
        $key = $this->keys->ensureActive();
        $cfg = Configuration::forAsymmetricSigner(new Sha256, InMemory::plainText($this->keys->privatePem($key)), InMemory::plainText('empty', 'empty'));
        $now = new DateTimeImmutable;
        $sub = (string) $at->getUserIdentifier();

        $b = $cfg->builder()
            ->issuedBy(config('vylaris.issuer'))
            ->permittedFor($at->getClient()->getIdentifier())
            ->relatedTo($sub)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify('+'.(int) config('vylaris.ttl.id_token').' seconds'))
            ->withHeader('kid', $key->kid)
            ->withClaim('azp', $at->getClient()->getIdentifier())
            ->withClaim('at_hash', self::halfHash($at->toString()));
        if ($this->ctx->authTime !== null) {
            $b = $b->withClaim('auth_time', $this->ctx->authTime);
        }
        if ($this->ctx->nonce !== null) {
            $b = $b->withClaim('nonce', $this->ctx->nonce);
        }
        if ($this->ctx->sid !== null) {
            $b = $b->withClaim('sid', SsoSessions::publicSid($this->ctx->sid));
        }
        if ($this->ctx->amr !== []) {
            $b = $b->withClaim('amr', $this->ctx->amr);
        }
        try {
            foreach (ClaimsBuilder::forScopes($this->dash->identity($sub), $scopes) as $k => $v) {
                $b = $b->withClaim($k, $v);
            }
        } catch (\Throwable) {
            // Minimales ID-Token; Details holt der Client ueber UserInfo.
        }

        return $b->getToken($cfg->signer(), $cfg->signingKey())->toString();
    }

    public static function halfHash(string $value): string
    {
        $h = hash('sha256', $value, true);

        return rtrim(strtr(base64_encode(substr($h, 0, 16)), '+/', '-_'), '=');
    }
}
