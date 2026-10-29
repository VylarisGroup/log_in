<?php

namespace App\Services\Vylaris;

use App\Models\Audit;
use App\Models\ServiceToken;
use App\Models\Setting;

/**
 * Lebenszyklus der Service-API-Token zwischen Dash und log_in.
 *
 * - Dash -> log_in ("inbound"): log_in erzeugt das Token, speichert nur den SHA-256-Hash (Token hat 256 Bit Entropie).
 * - log_in -> Dash ("outbound"): log_in erzeugt das Token ebenfalls, Dash speichert den Hash; log_in haelt es
 *   mit APP_KEY verschluesselt, um es senden zu koennen.
 * Token sind an die Dash-Installation und Scopes gebunden, laufen ab und sind widerrufbar. Rotation uebergibt beide
 * neuen Token als Sealed Box an Dash; das alte Inbound-Token bleibt nach der ersten Nutzung des neuen noch kurz gueltig.
 * Ed25519-Signaturschluessel sind davon getrennt (Schluesselrotation ist keine Token-Rotation).
 */
class ServiceTokens
{
    public const SCOPES = [
        'service.health' => 'Zustand abfragen',
        'pairings.manage' => 'Pairings anlegen, freigeben, ablehnen, bestaetigen',
        'clients.read' => 'OIDC-Clients (Kacheln) lesen',
        'clients.manage' => 'OIDC-Clients aendern, sperren, trennen, Geheimnis rotieren',
        'keys.manage' => 'OIDC-Signaturschluessel rotieren und widerrufen',
        'users.revoke' => 'Sitzungen widerrufen und Identitaets-Cache invalidieren',
        'service.rotate' => 'Service-Token rotieren',
    ];

    /** @return array{0: string, 1: ServiceToken} Klartext (einmalig) und Datensatz */
    public function issueInbound(string $installationId, ?array $scopes = null, ?int $rotatedFrom = null, bool $activated = true): array
    {
        $plain = 'vlst_'.rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $row = ServiceToken::query()->create([
            'token_hash' => self::hash($plain),
            'installation_id' => $installationId,
            'scopes' => array_values($scopes ?? array_keys(self::SCOPES)),
            'status' => 'active',
            'expires_at' => now()->addDays((int) config('vylaris.service_token.ttl_days')),
            'activated_at' => $activated ? now() : null,
            'rotated_from' => $rotatedFrom,
        ]);
        Audit::log('service_token.issued', 'system', (string) $row->id, ['installation' => $installationId, 'rotated_from' => $rotatedFrom]);

        return [$plain, $row];
    }

    public static function generateOutbound(): string
    {
        return 'vlst_'.rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function hash(string $plain): string
    {
        return hash('sha256', $plain);
    }

    public function outbound(): ?string
    {
        return Setting::get('dash.outbound_token') === null ? null : Setting::getSecret('dash.outbound_token');
    }

    /** Ersetzt alle Token der Installation (Bootstrap / erneute Anbindung). Liefert [inbound, outbound]. */
    public function bootstrap(string $installationId): array
    {
        ServiceToken::query()->where('status', 'active')->update(['status' => 'revoked', 'revoked_at' => now(), 'revoked_reason' => 'replaced']);
        [$inbound] = $this->issueInbound($installationId);
        $outbound = self::generateOutbound();
        Setting::putSecret('dash.outbound_token', $outbound);
        Setting::forget('dash.outbound_token_next');
        Setting::put('dash.outbound_token_expires_at', now()->addDays((int) config('vylaris.service_token.ttl_days'))->toIso8601String());

        return [$inbound, $outbound];
    }

    /**
     * Rotation: neues Inbound-Token (noch nicht aktiviert) und neues Outbound-Token; beides versiegelt fuer Dash.
     *
     * @return array{sealed: string, grace_seconds: int}
     *
     * @throws \InvalidArgumentException wenn kein X25519-Schluessel von Dash bekannt ist
     */
    public function rotate(string $installationId): array
    {
        $box = Setting::get('dash.box_public_key');
        if ($box === null) {
            throw new \InvalidArgumentException('dash_box_key_missing');
        }
        ServiceToken::query()->where('status', 'active')->whereNull('activated_at')->update(['status' => 'revoked', 'revoked_at' => now(), 'revoked_reason' => 'superseded']);
        $current = ServiceToken::query()->where('status', 'active')->whereNotNull('activated_at')->orderByDesc('id')->first();
        [$inbound, $row] = $this->issueInbound($installationId, null, $current?->id, false);
        $outbound = self::generateOutbound();
        Setting::putSecret('dash.outbound_token_next', $outbound);
        // Das alte Token darf nicht beliebig lange ueberleben, falls Dash das neue nie benutzt.
        $current?->update(['expires_at' => $current->expires_at->min(now()->addDay())]);
        Audit::log('service_token.rotated', 'dash', (string) $row->id);

        return [
            'sealed' => Signer::seal(json_encode([
                'service_token' => $inbound,
                'login_to_dash_token' => $outbound,
                'service_token_expires_at' => $row->expires_at->toIso8601String(),
            ], JSON_UNESCAPED_SLASHES), $box),
            'grace_seconds' => (int) config('vylaris.service_token.grace_minutes') * 60,
        ];
    }

    /** Erste Nutzung des neuen Inbound-Tokens = Empfangsbestaetigung: Outbound-Token wechselt, altes Token laeuft aus. */
    public function activate(ServiceToken $t): void
    {
        $t->update(['activated_at' => now()]);
        if ($next = Setting::get('dash.outbound_token_next')) {
            Setting::put('dash.outbound_token', $next);
            Setting::forget('dash.outbound_token_next');
            Setting::put('dash.outbound_token_expires_at', $t->expires_at->toIso8601String());
        }
        if ($t->rotated_from) {
            ServiceToken::query()->whereKey($t->rotated_from)->where('status', 'active')
                ->update(['expires_at' => now()->addMinutes((int) config('vylaris.service_token.grace_minutes'))]);
        }
        Audit::log('service_token.activated', 'dash', (string) $t->id);
    }

    public function revokeAll(string $reason = 'installation_revoked'): int
    {
        $n = ServiceToken::query()->where('status', 'active')->update(['status' => 'revoked', 'revoked_at' => now(), 'revoked_reason' => $reason]);
        Audit::log('service_token.revoked_all', 'cli', null, ['reason' => $reason, 'count' => $n]);

        return $n;
    }
}
