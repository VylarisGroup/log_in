<?php

namespace App\Services\Oidc;

use League\OAuth2\Server\Entities\ScopeEntityInterface;

final class ScopeEntity implements ScopeEntityInterface
{
    public function __construct(private readonly string $identifier) {}

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function jsonSerialize(): mixed
    {
        return $this->identifier;
    }
}
