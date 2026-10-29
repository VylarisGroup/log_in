<?php

namespace App\Services\Oidc;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;

final class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait, RefreshTokenTrait;
}
