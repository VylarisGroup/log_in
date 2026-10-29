<?php

namespace App\Services\Oidc;

use App\Services\Dash\DashClient;
use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;

/**
 * Baut den league/oauth2-server mit genau den unterstuetzten Grants:
 * authorization_code (PKCE S256 verpflichtend) und refresh_token. Implicit, Password, Client-Credentials und
 * Device-Code sind bewusst NICHT aktiviert.
 */
class ServerFactory
{
    public function __construct(
        private readonly KeyManager $keys,
        private readonly DashClient $dash,
        private readonly OidcContext $ctx,
    ) {}

    public function make(): AuthorizationServer
    {
        $this->ctx->reset(); // anfragebezogener Zustand darf nie zwischen Requests lecken
        $key = $this->keys->ensureActive();
        $access = new AccessTokenRepository($this->keys, $this->ctx);
        $refresh = new RefreshTokenRepository;
        $server = new AuthorizationServer(
            new ClientRepository,
            $access,
            new ScopeRepository,
            new CryptKey($this->keys->privatePem($key), null, false),
            self::encryptionKey(),
            new IdTokenResponse($this->keys, $this->dash, $this->ctx),
        );

        $code = new OidcAuthCodeGrant(new AuthCodeRepository($this->ctx), $refresh, new DateInterval('PT'.config('vylaris.ttl.auth_code').'S'), $this->ctx, $this->dash);
        $code->setRefreshTokenTTL(new DateInterval('PT'.config('vylaris.ttl.refresh_token').'S'));
        $server->enableGrantType($code, new DateInterval('PT'.config('vylaris.ttl.access_token').'S'));

        $rg = new OidcRefreshGrant($refresh, $this->ctx, $this->dash);
        $rg->setRefreshTokenTTL(new DateInterval('PT'.config('vylaris.ttl.refresh_token').'S'));
        $server->enableGrantType($rg, new DateInterval('PT'.config('vylaris.ttl.access_token').'S'));

        return $server;
    }

    public static function encryptionKey(): string
    {
        return hash('sha256', 'vylaris-oidc-v1|'.config('app.key'));
    }
}
