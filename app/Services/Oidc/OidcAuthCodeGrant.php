<?php

namespace App\Services\Oidc;

use App\Models\SsoSession;
use App\Services\Dash\DashClient;
use App\Services\Dash\DashUnavailableException;
use DateInterval;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authorization-Code-Grant mit erzwungenem PKCE (S256), Kontoprobe bei Dash, Nonce-/Sitzungsbindung fuer das ID-Token,
 * Widerruf bereits ausgestellter Tokens bei Code-Wiederverwendung und Refresh-Token nur mit offline_access.
 */
class OidcAuthCodeGrant extends AuthCodeGrant
{
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
        private readonly OidcContext $ctx,
        private readonly DashClient $dash,
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
    }

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, DateInterval $accessTokenTTL): ResponseTypeInterface
    {
        $verifier = $this->getRequestParameter('code_verifier', $request);
        if ($verifier === null || $verifier === '') {
            throw OAuthServerException::invalidRequest('code_verifier', 'PKCE ist verpflichtend');
        }

        $code = $this->getRequestParameter('code', $request);
        if ($code !== null) {
            try {
                $payload = json_decode($this->decrypt($code));
            } catch (\Throwable) {
                $payload = null;
            }
            if (is_object($payload) && isset($payload->auth_code_id)) {
                $row = DB::table('oidc_auth_codes')->where('id', $payload->auth_code_id)->first();
                if ($row !== null) {
                    if ((bool) $row->revoked) {
                        // Code-Wiederverwendung: bereits ausgestellte Tokens dieser Sitzung/dieses Clients widerrufen (RFC 6749 4.1.2).
                        DB::table('oidc_access_tokens')->where('sid', $row->sid)->where('client_id', $row->client_id)->update(['revoked' => true]);
                    } else {
                        $this->ctx->sid = $row->sid;
                        $this->ctx->nonce = $row->nonce;
                        $this->ctx->authTime = $row->auth_time ? strtotime($row->auth_time.' UTC') : null;
                        $this->ctx->userId = $row->user_id;
                        $this->ctx->amr = SsoSession::query()->find($row->sid)?->amr ?? [];
                        $this->ctx->issueIdToken = true;
                        $this->assertActive($row->user_id, false);
                    }
                }
            }
        }

        return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
    }

    private function assertActive(string $sub, bool $fresh): void
    {
        try {
            $id = $this->dash->identity($sub, $fresh);
        } catch (DashUnavailableException) {
            throw new OAuthServerException('Dash voruebergehend nicht erreichbar', 9, 'temporarily_unavailable', 503);
        } catch (\Throwable) {
            throw OAuthServerException::invalidGrant('Konto nicht pruefbar');
        }
        if (! $id->isActive()) {
            throw OAuthServerException::invalidGrant('Konto nicht aktiv');
        }
    }

    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        foreach ($accessToken->getScopes() as $s) {
            if ($s->getIdentifier() === 'offline_access') {
                return parent::issueRefreshToken($accessToken);
            }
        }

        return null;
    }
}
