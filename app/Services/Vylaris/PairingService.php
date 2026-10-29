<?php

namespace App\Services\Vylaris;

use App\Models\Audit;
use App\Models\OidcClient;
use App\Models\Pairing;
use App\Services\Oidc\SsoSessions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Serverseitiger Zustandsautomat des Vylaris Pairing Protocols (Seite log_in).
 *
 *   requested --dash-approve--> dash_approved --tool-confirm (Signatur ueber Challenge)--> active
 *   requested|dash_approved --dash-reject--> rejected | --cancel--> cancelled | Ablauf--> expired
 *   ungueltiger Nachweis --> failed
 *
 * Ein Client entsteht erst in "active". Die Challenge ist einmalig; Wiederholungen sind idempotent.
 */
class PairingService
{
    public function __construct(private readonly SsoSessions $sessions) {}

    /** @throws PairingException */
    public function request(array $d): Pairing
    {
        $existing = Pairing::query()->find($d['pairing_id']);
        if ($existing !== null) {
            if ($existing->installation_id !== $d['installation_id']) {
                throw new PairingException('pairing_conflict', 409);
            }

            return $this->tick($existing); // idempotenter Wiederholungsaufruf
        }
        if (OidcClient::query()->where('installation_id', $d['installation_id'])->whereIn('status', ['active', 'suspended', 'error'])->exists()) {
            throw new PairingException('installation_already_paired', 409);
        }
        if (Pairing::query()->where('installation_id', $d['installation_id'])->whereIn('state', ['requested', 'dash_approved'])->where('expires_at', '>', now())->exists()) {
            throw new PairingException('pairing_in_progress', 409);
        }
        $window = min(max((int) ($d['window_seconds'] ?? config('vylaris.pairing.window')), 30), (int) config('vylaris.pairing.max_window'));
        $p = Pairing::query()->create([
            'id' => $d['pairing_id'],
            'state' => 'requested',
            'installation_id' => $d['installation_id'],
            'name' => $d['name'],
            'domain' => strtolower($d['domain']),
            'version' => $d['version'] ?? null,
            'redirect_uris' => array_values($d['redirect_uris']),
            'post_logout_uris' => array_values($d['post_logout_uris'] ?? []),
            'scopes' => array_values(array_unique($d['scopes'])),
            'tool_sign_public_key' => $d['tool_sign_public_key'],
            'tool_box_public_key' => $d['tool_box_public_key'],
            'challenge' => Signer::randomNonce(),
            'expires_at' => now()->addSeconds($window),
        ]);
        Audit::log('pairing.requested', 'dash', $p->id, ['installation_id' => $p->installation_id, 'domain' => $p->domain]);

        return $p;
    }

    /** Markiert abgelaufene Pairings (kein Hintergrunddienst noetig: wird bei jedem Zugriff ausgewertet). */
    public function tick(Pairing $p): Pairing
    {
        if ($p->isExpired()) {
            $p->update(['state' => 'expired', 'sealed_credentials' => null]);
            Audit::log('pairing.expired', null, $p->id);
        }

        return $p->fresh();
    }

    /** @throws PairingException */
    public function approve(string $id): Pairing
    {
        $this->expireIfNeeded($id);

        return DB::transaction(function () use ($id) {
            $p = $this->lock($id);
            if ($p->state === 'dash_approved') {
                return $p;
            }
            if ($p->state !== 'requested') {
                throw new PairingException('invalid_state:'.$p->state, 409);
            }
            $p->update(['state' => 'dash_approved', 'dash_approved_at' => now()]);
            Audit::log('pairing.dash_approved', 'dash', $id);

            return $p->fresh();
        });
    }

    /** @throws PairingException */
    public function reject(string $id): Pairing
    {
        $this->expireIfNeeded($id);

        return DB::transaction(function () use ($id) {
            $p = $this->lock($id);
            if ($p->state === 'rejected') {
                return $p;
            }
            if (! in_array($p->state, ['requested', 'dash_approved'], true)) {
                throw new PairingException('invalid_state:'.$p->state, 409);
            }
            $p->update(['state' => 'rejected']);
            Audit::log('pairing.rejected', 'dash', $id);

            return $p->fresh();
        });
    }

    /** @throws PairingException */
    public function cancel(string $id): Pairing
    {
        $this->expireIfNeeded($id);

        return DB::transaction(function () use ($id) {
            $p = $this->lock($id);
            if ($p->state === 'cancelled') {
                return $p;
            }
            if ($p->isTerminal()) {
                throw new PairingException('invalid_state:'.$p->state, 409);
            }
            $p->update(['state' => 'cancelled']);
            Audit::log('pairing.cancelled', 'dash', $id);

            return $p->fresh();
        });
    }

    public static function proofMessage(Pairing $p): string
    {
        return implode("\n", ['VYLARIS-PAIR-V1', $p->id, $p->installation_id, $p->challenge, hash('sha256', json_encode([$p->redirect_uris, $p->scopes]))]);
    }

    /**
     * Schritt 7-9: Das Tool bestaetigt lokal (erneute Authentifizierung des Tool-Administrators) und signiert die Challenge
     * mit seinem Pairing-Schluessel. Erst nach gueltigem Nachweis werden Client und Zugangsdaten erzeugt.
     *
     * @throws PairingException
     */
    public function confirm(string $id, string $signature): Pairing
    {
        $this->expireIfNeeded($id);
        $failure = null;
        $result = DB::transaction(function () use ($id, $signature, &$failure) {
            $p = $this->lock($id);
            if ($p->state === 'active') {
                return $p; // idempotent: gleiche versiegelte Antwort, solange nicht quittiert
            }
            if ($p->state !== 'dash_approved') {
                throw new PairingException('invalid_state:'.$p->state, 409);
            }
            if ($p->challenge_used) {
                throw new PairingException('challenge_used', 409);
            }
            $p->update(['challenge_used' => true]);
            if (! Signer::verify(self::proofMessage($p), $signature, $p->tool_sign_public_key)) {
                // Fehlzustand wird committed; die Ausnahme folgt erst nach der Transaktion.
                $p->update(['state' => 'failed', 'failure_reason' => 'proof_invalid']);
                Audit::log('pairing.proof_invalid', 'dash', $id);
                $failure = new PairingException('proof_invalid', 422);

                return $p;
            }

            $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $client = OidcClient::query()->create([
                'client_id' => 'vl_'.Str::lower(bin2hex(random_bytes(12))),
                'installation_id' => $p->installation_id,
                'name' => $p->name,
                'domain' => $p->domain,
                'version' => $p->version,
                'confidential' => true,
                'secret_hash' => OidcClient::hashSecret($secret),
                'redirect_uris' => $p->redirect_uris,
                'post_logout_uris' => $p->post_logout_uris,
                'scopes' => $p->scopes,
                'status' => 'active',
                'pairing_id' => $p->id,
                'tool_public_key' => $p->tool_sign_public_key,
                'tool_box_public_key' => $p->tool_box_public_key,
            ]);
            $payload = json_encode([
                'issuer' => config('vylaris.issuer'),
                'client_id' => $client->client_id,
                'client_secret' => $secret,
                'token_endpoint_auth_method' => 'client_secret_basic',
            ], JSON_UNESCAPED_SLASHES);
            $p->update([
                'state' => 'active',
                'confirmed_at' => now(),
                'client_id' => $client->client_id,
                'sealed_credentials' => Signer::seal($payload, $p->tool_box_public_key),
            ]);
            Audit::log('pairing.activated', 'dash', $id, ['client_id' => $client->client_id]);

            return $p->fresh();
        });
        if ($failure !== null) {
            throw $failure;
        }

        return $result;
    }

    public function acknowledge(string $id): Pairing
    {
        $p = Pairing::query()->findOrFail($id);
        if ($p->state === 'active' && $p->credentials_acked_at === null) {
            $p->update(['credentials_acked_at' => now(), 'sealed_credentials' => null]);
        }

        return $p->fresh();
    }

    /** Neues Client-Geheimnis; das alte bleibt kurz gueltig (nahtloser Wechsel). Rueckgabe versiegelt. */
    public function rotateSecret(OidcClient $c): string
    {
        if (! $c->confidential || $c->tool_box_public_key === null) {
            throw new PairingException('rotation_not_supported', 422);
        }
        $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $c->update([
            'previous_secret_hash' => $c->secret_hash,
            'previous_secret_until' => now()->addMinutes(10),
            'secret_hash' => OidcClient::hashSecret($secret),
        ]);
        Audit::log('client.secret_rotated', 'dash', $c->client_id);

        return Signer::seal(json_encode(['client_id' => $c->client_id, 'client_secret' => $secret]), $c->tool_box_public_key);
    }

    public function disconnect(OidcClient $c, string $status = 'disconnected'): void
    {
        $c->update([
            'status' => $status,
            'disconnected_at' => $status === 'disconnected' ? now() : null,
            'secret_hash' => $status === 'disconnected' ? null : $c->secret_hash,
            'previous_secret_hash' => null,
            'previous_secret_until' => null,
        ]);
        $this->sessions->revokeTokensForClient($c->client_id);
        Audit::log('client.'.$status, 'dash', $c->client_id);
    }

    /** Markiert ein abgelaufenes Pairing ausserhalb jeder Transaktion, damit der Zustand erhalten bleibt. */
    private function expireIfNeeded(string $id): void
    {
        $p = Pairing::query()->find($id);
        if ($p !== null && $p->isExpired()) {
            $p->update(['state' => 'expired', 'sealed_credentials' => null]);
            Audit::log('pairing.expired', null, $id);
        }
    }

    private function lock(string $id): Pairing
    {
        $p = Pairing::query()->lockForUpdate()->findOrFail($id);
        if ($p->state === 'expired') {
            throw new PairingException('expired', 410);
        }

        return $p;
    }
}
