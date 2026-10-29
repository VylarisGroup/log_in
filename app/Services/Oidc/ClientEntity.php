<?php

namespace App\Services\Oidc;

use League\OAuth2\Server\Entities\ClientEntityInterface;

final class ClientEntity implements ClientEntityInterface
{
    /** @param  list<string>  $redirectUris */
    public function __construct(
        private readonly string $identifier,
        private readonly string $name,
        private readonly array $redirectUris,
        private readonly bool $confidential,
    ) {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRedirectUri(): string|array
    {
        return $this->redirectUris;
    }

    public function isConfidential(): bool
    {
        return $this->confidential;
    }
}
