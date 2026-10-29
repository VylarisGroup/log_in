<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Audit;
use App\Models\OidcClient;
use App\Models\Pairing;
use App\Models\SigningKey;
use App\Services\Dash\DashClient;
use App\Services\Oidc\KeyManager;
use App\Services\Oidc\SsoSessions;
use App\Services\Vylaris\PairingException;
use App\Services\Vylaris\PairingService;
use App\Services\Vylaris\UriPolicy;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

/**
 * Verwaltungs-API fuer Dash (/api/dash/v1). Authentifizierung ausschliesslich ueber VerifyDashSignature.
 * Reseller und Tools duerfen diese API nie direkt aufrufen.
 */
class DashApiController extends Controller
{
    public function __construct(
        private readonly PairingService $pairings,
        private readonly KeyManager $keys,
        private readonly SsoSessions $sessions,
    ) {}

    public function health(): JsonResponse
    {
        return response()->json([
            'status' => 'ok',
            'version' => config('vylaris.version'),
            'issuer' => config('vylaris.issuer'),
            'active_kid' => $this->keys->active()?->kid,
            'time' => now()->toIso8601String(),
        ]);
    }

    // ---- Pairing -------------------------------------------------------------------------------------------

    public function pairingCreate(Request $r): JsonResponse
    {
        $v = Validator::make($r->json()->all(), [
            'pairing_id' => ['required', 'regex:/^[A-Za-z0-9_\-]{16,64}$/'],
            'installation_id' => ['required', 'string', 'regex:/^[A-Za-z0-9_.:\-]{8,128}$/'],
            'name' => ['required', 'string', 'max:100'],
            'domain' => ['required', 'string', 'max:253'],
            'version' => ['nullable', 'string', 'max:32'],
            'redirect_uris' => ['required', 'array', 'min:1', 'max:10'],
            'post_logout_uris' => ['nullable', 'array', 'max:10'],
            'scopes' => ['required', 'array', 'min:1', 'max:10'],
            'scopes.*' => ['string', 'in:'.implode(',', array_keys(config('vylaris.scopes')))],
            'tool_sign_public_key' => ['required', 'string', 'max:128'],
            'tool_box_public_key' => ['required', 'string', 'max:128'],
            'window_seconds' => ['nullable', 'integer', 'min:30', 'max:'.config('vylaris.pairing.max_window')],
        ]);
        $errors = $v->errors()->all();
        $d = $v->fails() ? [] : $v->validated();
        if (! $v->fails()) {
            if (! UriPolicy::validDomain($d['domain'])) {
                $errors[] = 'ungueltige Domain';
            }
            if (! in_array('openid', $d['scopes'], true)) {
                $errors[] = 'Scope openid ist erforderlich';
            }
            if (strlen(base64_decode($d['tool_sign_public_key'], true) ?: '') !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                $errors[] = 'tool_sign_public_key ist kein Ed25519-Schluessel';
            }
            if (strlen(base64_decode($d['tool_box_public_key'], true) ?: '') !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
                $errors[] = 'tool_box_public_key ist kein X25519-Schluessel';
            }
            $errors = array_merge($errors, UriPolicy::validate($d['redirect_uris'], $d['domain']), UriPolicy::validate($d['post_logout_uris'] ?? [], $d['domain'], false));
        }
        if ($errors !== []) {
            return response()->json(['error' => 'validation_failed', 'details' => array_values($errors)], 422);
        }
        try {
            $p = $this->pairings->request($d);
        } catch (PairingException $e) {
            return response()->json(['error' => $e->getMessage()], $e->status);
        }

        return response()->json($this->pairingView($p), $p->wasRecentlyCreated ? 201 : 200);
    }

    public function pairingShow(string $id): JsonResponse
    {
        $p = Pairing::query()->find($id);
        if ($p === null) {
            return response()->json(['error' => 'not_found'], 404);
        }

        return response()->json($this->pairingView($this->pairings->tick($p)));
    }

    public function pairingAction(Request $r, string $id, string $action): JsonResponse
    {
        try {
            $p = match ($action) {
                'dash-approve' => $this->pairings->approve($id),
                'dash-reject' => $this->pairings->reject($id),
                'cancel' => $this->pairings->cancel($id),
                'credentials-ack' => $this->pairings->acknowledge($id),
                'tool-confirm' => $this->pairings->confirm($id, (string) $r->json('proof')),
                default => null,
            };
        } catch (PairingException $e) {
            return response()->json(['error' => $e->getMessage()], $e->status);
        } catch (ModelNotFoundException) {
            return response()->json(['error' => 'not_found'], 404);
        }
        if ($p === null) {
            return response()->json(['error' => 'not_found'], 404);
        }

        return response()->json($this->pairingView($p));
    }

    /** @return array<string, mixed> */
    private function pairingView(Pairing $p): array
    {
        $v = [
            'pairing_id' => $p->id,
            'state' => $p->state,
            'installation_id' => $p->installation_id,
            'name' => $p->name,
            'domain' => $p->domain,
            'version' => $p->version,
            'scopes' => $p->scopes,
            'redirect_uris' => $p->redirect_uris,
            'expires_at' => $p->expires_at->toIso8601String(),
            'dash_approved_at' => $p->dash_approved_at?->toIso8601String(),
            'confirmed_at' => $p->confirmed_at?->toIso8601String(),
            'failure_reason' => $p->failure_reason,
        ];
        if (in_array($p->state, ['requested', 'dash_approved'], true)) {
            $v['challenge'] = $p->challenge;
        }
        if ($p->state === 'active') {
            $v['client_id'] = $p->client_id;
            if ($p->credentials_acked_at === null) {
                $v['sealed_credentials'] = $p->sealed_credentials;
            }
        }

        return $v;
    }

    // ---- Clients / Kacheln ---------------------------------------------------------------------------------

    public function clientIndex(): JsonResponse
    {
        $tiles = OidcClient::query()->orderBy('name')->get()->map->toTile()->all();
        $pending = Pairing::query()->whereIn('state', ['requested', 'dash_approved'])->where('expires_at', '>', now())->get()
            ->map(fn (Pairing $p) => ['pairing_id' => $p->id, 'installation_id' => $p->installation_id, 'name' => $p->name, 'domain' => $p->domain, 'status' => 'pending', 'state' => $p->state])->all();

        return response()->json(['clients' => $tiles, 'pending_pairings' => $pending]);
    }

    public function clientShow(string $id): JsonResponse
    {
        $c = OidcClient::query()->find($id);

        return $c === null ? response()->json(['error' => 'not_found'], 404) : response()->json($c->toTile());
    }

    public function clientUpdate(Request $r, string $id): JsonResponse
    {
        $c = OidcClient::query()->find($id);
        if ($c === null) {
            return response()->json(['error' => 'not_found'], 404);
        }
        $d = $r->json()->all();
        $errors = [];
        $upd = [];
        foreach (['redirect_uris' => true, 'post_logout_uris' => false] as $f => $req) {
            if (array_key_exists($f, $d)) {
                $errs = is_array($d[$f]) ? UriPolicy::validate($d[$f], $c->domain, $req) : ['array erwartet'];
                $errors = array_merge($errors, $errs);
                $upd[$f] = is_array($d[$f]) ? array_values($d[$f]) : [];
            }
        }
        if (array_key_exists('scopes', $d)) {
            if (! is_array($d['scopes']) || array_diff($d['scopes'], array_keys(config('vylaris.scopes'))) !== [] || ! in_array('openid', $d['scopes'], true)) {
                $errors[] = 'ungueltige Scopes';
            }
            $upd['scopes'] = array_values(array_unique($d['scopes'] ?? []));
        }
        if (isset($d['version']) && is_string($d['version']) && strlen($d['version']) <= 32) {
            $upd['version'] = $d['version'];
        }
        if ($errors !== []) {
            return response()->json(['error' => 'validation_failed', 'details' => $errors], 422);
        }
        $c->update($upd);
        Audit::log('client.updated', 'dash', $c->client_id, ['fields' => array_keys($upd)]);

        return response()->json($c->fresh()->toTile());
    }

    public function clientAction(string $id, string $action): JsonResponse
    {
        $c = OidcClient::query()->find($id);
        if ($c === null) {
            return response()->json(['error' => 'not_found'], 404);
        }
        if ($c->is_dash && in_array($action, ['disconnect', 'suspend'], true)) {
            return response()->json(['error' => 'dash_client_protected'], 409);
        }
        switch ($action) {
            case 'suspend':
                $this->pairings->disconnect($c, 'suspended');
                break;
            case 'resume':
                if ($c->status !== 'suspended') {
                    return response()->json(['error' => 'invalid_state:'.$c->status], 409);
                }
                $c->update(['status' => 'active', 'last_error' => null]);
                Audit::log('client.resumed', 'dash', $c->client_id);
                break;
            case 'disconnect':
                $this->pairings->disconnect($c, 'disconnected');
                break;
            case 'report-error':
                $c->update(['status' => 'error', 'last_error' => 'vom Tool oder Dash gemeldet']);
                Audit::log('client.error_reported', 'dash', $c->client_id);
                break;
            case 'rotate-secret':
                try {
                    $sealed = $this->pairings->rotateSecret($c);
                } catch (PairingException $e) {
                    return response()->json(['error' => $e->getMessage()], $e->status);
                }

                return response()->json(['client_id' => $c->client_id, 'sealed_credentials' => $sealed, 'previous_secret_valid_until' => $c->fresh()->previous_secret_until->toIso8601String()]);
            default:
                return response()->json(['error' => 'not_found'], 404);
        }

        return response()->json($c->fresh()->toTile());
    }

    // ---- Schluessel ----------------------------------------------------------------------------------------

    public function keyIndex(): JsonResponse
    {
        return response()->json(['keys' => SigningKey::query()->orderByDesc('created_at')->get(['kid', 'alg', 'status', 'activated_at', 'retire_after'])]);
    }

    public function keyRotate(): JsonResponse
    {
        $k = $this->keys->rotate('dash');

        return response()->json(['kid' => $k->kid, 'status' => $k->status], 201);
    }

    public function keyRevoke(string $kid): JsonResponse
    {
        if (! SigningKey::query()->whereKey($kid)->exists()) {
            return response()->json(['error' => 'not_found'], 404);
        }
        $this->keys->revoke($kid, 'dash');

        return response()->json(['kid' => $kid, 'status' => 'revoked']);
    }

    // ---- Rechteentzug --------------------------------------------------------------------------------------

    /** Dash meldet: Konto gesperrt/geloescht/Rollen geaendert. Sitzungen und Tokens erlöschen sofort. */
    public function userRevoke(Request $r, string $sub): JsonResponse
    {
        if ($sub === '' || strlen($sub) > 128) {
            return response()->json(['error' => 'bad_sub'], 422);
        }
        $n = $this->sessions->revokeForUser($sub, (string) ($r->json('reason') ?? 'dash_revocation'));
        app(DashClient::class)->forgetIdentity($sub);

        return response()->json(['sub' => $sub, 'revoked_sessions' => $n]);
    }

    /** Rollen-/Mandantenaenderung ohne Sperre: nur Cache invalidieren, naechster Zugriff holt frische Daten. */
    public function userRefresh(string $sub): JsonResponse
    {
        app(DashClient::class)->forgetIdentity($sub);
        Audit::log('user.identity_refresh', 'dash', $sub);

        return response()->json(['sub' => $sub, 'cache' => 'invalidated']);
    }
}
