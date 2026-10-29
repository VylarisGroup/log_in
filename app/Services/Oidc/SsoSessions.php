<?php

namespace App\Services\Oidc;

use App\Models\Audit;
use App\Models\SsoSession;
use Illuminate\Support\Facades\DB;

/**
 * Serverseitige SSO-Sitzungen. Die Sitzungszeile ist massgeblich: Widerruf, Idle- und Absolutablauf werden hier
 * entschieden, nicht im Cookie.
 */
class SsoSessions
{
    /** @param  list<string>  $amr */
    public function create(string $sub, ?string $tenantId, array $amr): SsoSession
    {
        $id = bin2hex(random_bytes(32));

        return SsoSession::query()->create([
            'id' => $id,
            'public_sid' => self::publicSid($id),
            'sub' => $sub,
            'tenant_id' => $tenantId,
            'auth_time' => now(),
            'last_seen_at' => now(),
            'expires_at' => now()->addSeconds((int) config('vylaris.ttl.sso_absolute')),
            'amr' => $amr,
        ]);
    }

    public static function publicSid(string $sid): string
    {
        return substr(hash('sha256', $sid), 0, 32);
    }

    public function valid(?string $sid, bool $touch = true): ?SsoSession
    {
        if ($sid === null || $sid === '') {
            return null;
        }
        $s = SsoSession::query()->find($sid);
        if ($s === null || ! $s->isValid()) {
            return null;
        }
        if ($touch) {
            $s->update(['last_seen_at' => now()]);
        }

        return $s;
    }

    public function revoke(string $sid, string $reason): void
    {
        $s = SsoSession::query()->find($sid);
        if ($s !== null && $s->revoked_at === null) {
            $s->update(['revoked_at' => now(), 'revoked_reason' => $reason]);
            Audit::log('session.revoked', null, $s->sub, ['sid_hash' => substr(hash('sha256', $sid), 0, 12), 'reason' => $reason]);
        }
        $this->revokeTokens(fn ($q) => $q->where('sid', $sid));
    }

    public function revokeForUser(string $sub, string $reason): int
    {
        $n = SsoSession::query()->where('sub', $sub)->whereNull('revoked_at')->update(['revoked_at' => now(), 'revoked_reason' => $reason]);
        $this->revokeTokens(fn ($q) => $q->where('user_id', $sub));
        Audit::log('user.sessions_revoked', 'dash', $sub, ['reason' => $reason, 'sessions' => $n]);

        return $n;
    }

    public function revokeTokensForClient(string $clientId): void
    {
        $this->revokeTokens(fn ($q) => $q->where('client_id', $clientId));
    }

    private function revokeTokens(\Closure $scope): void
    {
        $ids = $scope(DB::table('oidc_access_tokens'))->pluck('id');
        if ($ids->isEmpty()) {
            return;
        }
        foreach ($ids->chunk(500) as $chunk) {
            DB::table('oidc_access_tokens')->whereIn('id', $chunk)->update(['revoked' => true]);
            DB::table('oidc_refresh_tokens')->whereIn('access_token_id', $chunk)->update(['revoked' => true]);
        }
    }

    public function purgeExpired(): void
    {
        DB::table('oidc_auth_codes')->where('expires_at', '<', now()->subDay())->delete();
        DB::table('oidc_access_tokens')->where('expires_at', '<', now()->subDay())->delete();
        DB::table('oidc_refresh_tokens')->where('expires_at', '<', now()->subDay())->delete();
        SsoSession::query()->where('expires_at', '<', now()->subDays(7))->delete();
        DB::table('api_nonces')->where('expires_at', '<', now())->delete();
    }
}
