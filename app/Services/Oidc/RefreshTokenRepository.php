<?php

namespace App\Services\Oidc;

use App\Models\SsoSession;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity;
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        DB::table('oidc_refresh_tokens')->insert([
            'id' => $refreshTokenEntity->getIdentifier(),
            'access_token_id' => $refreshTokenEntity->getAccessToken()->getIdentifier(),
            'revoked' => false,
            'expires_at' => $refreshTokenEntity->getExpiryDateTime(),
        ]);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        DB::table('oidc_refresh_tokens')->where('id', $tokenId)->update(['revoked' => true]);
    }

    /** Wiederverwendung eines bereits benutzten Refresh-Tokens (Replay) widerruft die ganze Sitzung. */
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $row = DB::table('oidc_refresh_tokens')->where('id', $tokenId)->first();
        if ($row === null) {
            return true;
        }
        if ((bool) $row->revoked) {
            $sid = DB::table('oidc_access_tokens')->where('id', $row->access_token_id)->value('sid');
            if ($sid !== null) {
                app(SsoSessions::class)->revoke($sid, 'refresh_token_reuse');
            }

            return true;
        }
        $sid = DB::table('oidc_access_tokens')->where('id', $row->access_token_id)->value('sid');
        if ($sid !== null) {
            $s = SsoSession::query()->find($sid);
            if ($s === null || $s->revoked_at !== null || $s->expires_at->isPast()) {
                return true;
            }
        }

        return false;
    }
}
