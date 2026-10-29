<?php

namespace App\Services\Oidc;

use App\Models\OidcClient;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

final class ScopeRepository implements ScopeRepositoryInterface
{
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return array_key_exists($identifier, config('vylaris.scopes')) ? new ScopeEntity($identifier) : null;
    }

    /** Beschraenkt auf die dem Client erlaubten Scopes; zusaetzliche Scopes werden abgelehnt (kein stilles Erweitern). */
    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        $allowed = OidcClient::query()->find($clientEntity->getIdentifier())?->scopes ?? [];
        foreach ($scopes as $s) {
            if (! in_array($s->getIdentifier(), $allowed, true)) {
                throw OAuthServerException::invalidScope($s->getIdentifier());
            }
        }

        return $scopes;
    }
}
