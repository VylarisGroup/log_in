<?php

namespace App\Services\Oidc;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

final class AuthCodeEntity implements AuthCodeEntityInterface
{
    use AuthCodeTrait, EntityTrait, TokenEntityTrait;
}
