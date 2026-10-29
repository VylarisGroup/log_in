<?php

namespace App\Services\Oidc;

use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

final class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(private readonly OidcContext $ctx) {}

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCodeEntity;
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        DB::table('oidc_auth_codes')->insert([
            'id' => $authCodeEntity->getIdentifier(),
            'user_id' => $authCodeEntity->getUserIdentifier(),
            'client_id' => $authCodeEntity->getClient()->getIdentifier(),
            'scopes' => json_encode(array_map(fn ($s) => $s->getIdentifier(), $authCodeEntity->getScopes())),
            'revoked' => false,
            'expires_at' => $authCodeEntity->getExpiryDateTime(),
            'nonce' => $this->ctx->nonce,
            'sid' => $this->ctx->sid,
            'auth_time' => $this->ctx->authTime === null ? null : date('Y-m-d H:i:s', $this->ctx->authTime),
        ]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        DB::table('oidc_auth_codes')->where('id', $codeId)->update(['revoked' => true]);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $r = DB::table('oidc_auth_codes')->where('id', $codeId)->value('revoked');

        return $r === null || (bool) $r;
    }
}
