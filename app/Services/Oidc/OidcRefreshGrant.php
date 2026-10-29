<?php

namespace App\Services\Oidc;

use App\Services\Dash\DashClient;
use App\Services\Dash\DashUnavailableException;
use DateInterval;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Refresh-Grant: rotierende Einmal-Token; vor jeder Ausstellung wird das Konto frisch (ohne Cache) bei Dash geprueft.
 * Ist Dash nicht erreichbar, wird nichts ausgestellt (fail closed).
 */
class OidcRefreshGrant extends RefreshTokenGrant
{
    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly OidcContext $ctx,
        private readonly DashClient $dash,
    ) {
        parent::__construct($refreshTokenRepository);
    }

    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseTypeInterface $responseType, DateInterval $accessTokenTTL): ResponseTypeInterface
    {
        $raw = $this->getRequestParameter('refresh_token', $request);
        if ($raw !== null) {
            try {
                $payload = json_decode($this->decrypt($raw));
            } catch (\Throwable) {
                $payload = null;
            }
            if (is_object($payload) && isset($payload->access_token_id)) {
                $old = DB::table('oidc_access_tokens')->where('id', $payload->access_token_id)->first();
                if ($old !== null) {
                    $this->ctx->sid = $old->sid;
                    try {
                        $identity = $this->dash->identity((string) $old->user_id, true);
                    } catch (DashUnavailableException) {
                        throw new OAuthServerException('Dash voruebergehend nicht erreichbar', 9, 'temporarily_unavailable', 503);
                    } catch (\Throwable) {
                        throw OAuthServerException::invalidGrant('Konto nicht pruefbar');
                    }
                    if (! $identity->isActive()) {
                        app(SsoSessions::class)->revokeForUser((string) $old->user_id, 'account_inactive');
                        throw OAuthServerException::invalidGrant('Konto nicht aktiv');
                    }
                }
            }
        }

        return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
    }
}
