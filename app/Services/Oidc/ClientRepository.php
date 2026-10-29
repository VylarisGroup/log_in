<?php

namespace App\Services\Oidc;

use App\Models\OidcClient;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final class ClientRepository implements ClientRepositoryInterface
{
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $c = OidcClient::query()->find($clientIdentifier);
        if ($c === null || ! $c->isUsable()) {
            return null;
        }

        return new ClientEntity($c->client_id, $c->name, $c->redirect_uris, $c->confidential);
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $c = OidcClient::query()->find($clientIdentifier);
        if ($c === null || ! $c->isUsable()) {
            return false;
        }
        if ($grantType !== null && ! in_array($grantType, ['authorization_code', 'refresh_token'], true)) {
            return false;
        }
        if (! $c->confidential) {
            return true; // oeffentliche Clients: PKCE ist verpflichtend (siehe OidcAuthCodeGrant)
        }

        return $clientSecret !== null && $clientSecret !== '' && $c->secretMatches($clientSecret);
    }
}
