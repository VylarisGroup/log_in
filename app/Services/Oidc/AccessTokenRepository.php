<?php

namespace App\Services\Oidc;

use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(private readonly KeyManager $keys, private readonly OidcContext $ctx) {}

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        $t = new AccessTokenEntity;
        $t->setClient($clientEntity);
        foreach ($scopes as $s) {
            $t->addScope($s);
        }
        if ($userIdentifier !== null) {
            $t->setUserIdentifier($userIdentifier);
        }
        $key = $this->keys->ensureActive();
        $t->setSigningKey($key->kid, $this->keys->privatePem($key));
        $t->sid = $this->ctx->sid;

        return $t;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        DB::table('oidc_access_tokens')->insert([
            'id' => $accessTokenEntity->getIdentifier(),
            'user_id' => $accessTokenEntity->getUserIdentifier(),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'scopes' => json_encode(array_map(fn ($s) => $s->getIdentifier(), $accessTokenEntity->getScopes())),
            'revoked' => false,
            'expires_at' => $accessTokenEntity->getExpiryDateTime(),
            'sid' => $this->ctx->sid,
            'created_at' => now(),
        ]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        DB::table('oidc_access_tokens')->where('id', $tokenId)->update(['revoked' => true]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $r = DB::table('oidc_access_tokens')->where('id', $tokenId)->value('revoked');

        return $r === null || (bool) $r;
    }
}
