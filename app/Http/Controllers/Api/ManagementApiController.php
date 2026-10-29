<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Audit;
use App\Models\OidcClient;
use App\Models\Pairing;
use App\Models\Setting;
use App\Models\SigningKey;
use App\Services\Dash\DashClient;
use App\Services\Oidc\KeyManager;
use App\Services\Oidc\SsoSessions;
use App\Services\Vylaris\PairingException;
use App\Services\Vylaris\PairingService;
use App\Services\Vylaris\ServiceTokens;
use App\Services\Vylaris\SsrfGuard;
use App\Services\Vylaris\UriPolicy;
use App\Support\ApiError;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

/**
 * Verwaltungs-API fuer Dash (/api/vylaris/v1). Authentifizierung ausschliesslich ueber VerifyMachineRequest
 * (Bearer-Service-Token + Ed25519-Signatur). Reseller und Tools duerfen diese API nie direkt aufrufen.
 */
class ManagementApiController extends Controller
{
    public function __construct(
        private readonly PairingService $pairings,
        private readonly KeyManager $keys,
        private readonly SsoSessions $sessions,
    ) {}

    public function health(): JsonResponse
    {
        return ApiError::data([
            'status' => 'ok',
            'version' => config('vylaris.version'),
            'api_version' => config('vylaris.api_version'),
            'issuer' => config('vylaris.issuer'),
            'active_key_id' => $this->keys->active()?->kid,
            'service_token_expires_at' => Setting::get('dash.outbound_token_expires_at'),
            'time' => now()->toIso8601String(),
        ]);
    }

    // ---- Pairing -------------------------------------------------------------------------------------------

    public function pairingCreate(Request $r): JsonResponse
    {
        $v = Validator::make($r->json()->all(), [
            'pairing_id' => ['required', 'regex:/^[A-Za-z0-9_\-]{16,64}$/'],
            'installation_id' => ['required', 'string', 'regex:/^[A-Za-z0-9_.:\-]{8,128}$/'],
            'tool_id' => ['required', 'string', 'regex:/^[a-z0-9][a-z0-9_.-]{1,63}$/'],
            'name' => ['required', 'string', 'max:100'],
            'base_url' => ['required', 'string', 'max:255'],
            'version' => ['nullable', 'string', 'max:32'],
            'redirect_uris' => ['required', 'array', 'min:1', 'max:10'],
            'post_logout_uris' => ['nullable', 'array', 'max:10'],
            'scopes' => ['required', 'array', 'min:1', 'max:10'],
            'scopes.*' => ['string', 'in:'.implode(',', array_keys(config('vylaris.scopes')))],
            'tool_sign_public_key' => ['required', 'string', 'max:128'],
            'tool_box_public_key' => ['required', 'string', 'max:128'],
        ]);
        $errors = $v->errors()->all();
        $d = $v->fails() ? [] : $v->validated();
        if (! $v->fails()) {
            $host = strtolower((string) parse_url($d['base_url'], PHP_URL_HOST));
            if ($host === '' || ! UriPolicy::validDomain($host)) {
                $errors[] = 'base_url: ungueltiger Host';
            } else {
                $errors = array_merge($errors, array_map(fn ($e) => 'base_url: '.$e, UriPolicy::validate([$d['base_url']], $host)));
                if (filter_var($host, FILTER_VALIDATE_IP) && ! SsrfGuard::isPublic($host) && ! SsrfGuard::relaxed()) {
                    $errors[] = 'base_url: nicht oeffentliche Adresse nicht zulaessig';
                }
                $d['domain'] = $host;
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
            $errors = array_merge($errors, UriPolicy::validate($d['redirect_uris'], $d['domain'] ?? ''), UriPolicy::validate($d['post_logout_uris'] ?? [], $d['domain'] ?? '', false));
        }
        if ($errors !== []) {
            return ApiError::response('validation_failed', null, array_values($errors));
        }
        try {
            $p = $this->pairings->request($d);
        } catch (PairingException $e) {
            return $this->pairingError($e);
        }

        return ApiError::data($this->pairingView($p), $p->wasRecentlyCreated ? 201 : 200);
    }

    public function windowShow(): JsonResponse
    {
        $end = $this->pairings->windowEnd();

        return ApiError::data(['open' => $end !== null, 'expires_at' => $end?->toIso8601String()]);
    }

    public function windowOpen(Request $r): JsonResponse
    {
        $v = Validator::make($r->json()->all(), ['duration_seconds' => ['nullable', 'integer', 'min:30', 'max:'.config('vylaris.pairing.max_window')]]);
        if ($v->fails()) {
            return ApiError::response('validation_failed', null, $v->errors()->all());
        }
        $end = $this->pairings->openWindow($v->validated()['duration_seconds'] ?? null);

        return ApiError::data(['open' => true, 'expires_at' => $end->toIso8601String()], 201);
    }

    public function windowClose(): JsonResponse
    {
        $this->pairings->closeWindow();

        return ApiError::data(['open' => false, 'expires_at' => null]);
    }

    public function pairingShow(string $id): JsonResponse
    {
        $p = Pairing::query()->find($id);
        if ($p === null) {
            return ApiError::response('resource_not_found');
        }

        return ApiError::data($this->pairingView($this->pairings->tick($p)));
    }

    public function pairingAction(Request $r, string $id, string $action): JsonResponse
    {
        try {
            $p = match ($action) {
                'approve' => $this->pairings->approve($id, is_array($sc = ($r->json()->all()['approved_scopes'] ?? null)) ? $sc : null),
                'reject' => $this->pairings->reject($id),
                'cancel' => $this->pairings->cancel($id),
                'credentials-ack' => $this->pairings->acknowledge($id),
                'confirm' => $this->pairings->confirm($id, (string) $r->json('proof')),
                default => null,
            };
        } catch (PairingException $e) {
            return $this->pairingError($e);
        } catch (ModelNotFoundException) {
            return ApiError::response('resource_not_found');
        }
        if ($p === null) {
            return ApiError::response('resource_not_found');
        }

        return ApiError::data($this->pairingView($p));
    }

    private function pairingError(PairingException $e): JsonResponse
    {
        $m = $e->getMessage();

        return match (true) {
            in_array($m, ['pairing_conflict', 'installation_already_paired', 'pairing_in_progress'], true) => ApiError::response('duplicate_conflict', null, ['reason' => $m]),
            $m === 'expired' => ApiError::response('pairing_expired'),
            $m === 'window_closed' => ApiError::response('pairing_closed', 'No pairing window is open', ['reason' => $m]),
            $m === 'invalid_approved_scopes' => ApiError::response('validation_failed', 'approved_scopes must be a non-empty subset of the requested scopes including openid', ['reason' => $m]),
            in_array($m, ['proof_invalid', 'challenge_used'], true) => ApiError::response('invalid_pairing_proof', null, ['reason' => $m], $e->status),
            $m === 'invalid_state:rejected' => ApiError::response('pairing_denied'),
            str_starts_with($m, 'invalid_state:') => ApiError::response('pairing_closed', null, ['state' => substr($m, 14)]),
            default => ApiError::response('validation_failed', null, ['reason' => $m]),
        };
    }

    /** @return array<string, mixed> */
    private function pairingView(Pairing $p): array
    {
        $v = [
            'pairing_id' => $p->id,
            'state' => $p->state,
            'installation_id' => $p->installation_id,
            'tool_id' => $p->tool_id,
            'name' => $p->name,
            'base_url' => $p->base_url,
            'domain' => $p->domain,
            'version' => $p->version,
            'scopes' => $p->scopes,
            'approved_scopes' => $p->approved_scopes,
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
            ->map(fn (Pairing $p) => ['pairing_id' => $p->id, 'installation_id' => $p->installation_id, 'tool_id' => $p->tool_id, 'name' => $p->name, 'domain' => $p->domain, 'status' => 'pending', 'state' => $p->state])->all();

        return ApiError::data($tiles, 200, ['pending_pairings' => $pending, 'total' => count($tiles)]);
    }

    public function clientShow(string $id): JsonResponse
    {
        $c = OidcClient::query()->find($id);

        return $c === null ? ApiError::response('resource_not_found') : ApiError::data($c->toTile());
    }

    public function clientUpdate(Request $r, string $id): JsonResponse
    {
        $c = OidcClient::query()->find($id);
        if ($c === null) {
            return ApiError::response('resource_not_found');
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
            return ApiError::response('validation_failed', null, $errors);
        }
        $c->update($upd);
        Audit::log('client.updated', 'dash', $c->client_id, ['fields' => array_keys($upd)]);

        return ApiError::data($c->fresh()->toTile());
    }

    public function clientAction(string $id, string $action): JsonResponse
    {
        $c = OidcClient::query()->find($id);
        if ($c === null) {
            return ApiError::response('resource_not_found');
        }
        if ($c->is_dash && in_array($action, ['disconnect', 'suspend'], true)) {
            return ApiError::response('forbidden', 'The Dash client cannot be suspended or disconnected', ['reason' => 'dash_client_protected']);
        }
        switch ($action) {
            case 'suspend':
                $this->pairings->disconnect($c, 'suspended');
                break;
            case 'resume':
                if ($c->status !== 'suspended') {
                    return ApiError::response('pairing_closed', 'Client is not suspended', ['state' => $c->status]);
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
                    return $this->pairingError($e);
                }

                return ApiError::data(['client_id' => $c->client_id, 'sealed_credentials' => $sealed, 'previous_secret_valid_until' => $c->fresh()->previous_secret_until->toIso8601String()]);
            default:
                return ApiError::response('resource_not_found');
        }

        return ApiError::data($c->fresh()->toTile());
    }

    // ---- Schluessel ----------------------------------------------------------------------------------------

    public function keyIndex(): JsonResponse
    {
        $keys = SigningKey::query()->orderByDesc('created_at')->get(['kid', 'alg', 'status', 'activated_at', 'retire_after'])->map(fn ($k) => ['key_id' => $k->kid, 'alg' => $k->alg, 'status' => $k->status, 'activated_at' => $k->activated_at?->toIso8601String(), 'retire_after' => $k->retire_after?->toIso8601String()])->all();

        return ApiError::data($keys, 200, ['total' => count($keys)]);
    }

    public function keyRotate(): JsonResponse
    {
        $k = $this->keys->rotate('dash');

        return ApiError::data(['key_id' => $k->kid, 'status' => $k->status], 201);
    }

    public function keyRevoke(string $key_id): JsonResponse
    {
        $kid = $key_id;
        if (! SigningKey::query()->whereKey($kid)->exists()) {
            return ApiError::response('resource_not_found');
        }
        $this->keys->revoke($kid, 'dash');

        return ApiError::data(['key_id' => $kid, 'status' => 'revoked']);
    }

    // ---- Rechteentzug --------------------------------------------------------------------------------------

    /** Dash meldet: Konto gesperrt/geloescht/Rollen geaendert. Sitzungen und Tokens erlöschen sofort. */
    public function userRevoke(Request $r, string $sub): JsonResponse
    {
        if ($sub === '' || strlen($sub) > 128) {
            return ApiError::response('validation_failed', null, ['sub' => 'invalid']);
        }
        $n = $this->sessions->revokeForUser($sub, (string) ($r->json('reason') ?? 'dash_revocation'));
        app(DashClient::class)->forgetIdentity($sub);

        return ApiError::data(['sub' => $sub, 'revoked_sessions' => $n]);
    }

    /** Rollen-/Mandantenaenderung ohne Sperre: nur Cache invalidieren, naechster Zugriff holt frische Daten. */
    public function userRefresh(string $sub): JsonResponse
    {
        app(DashClient::class)->forgetIdentity($sub);
        Audit::log('user.identity_refresh', 'dash', $sub);

        return ApiError::data(['sub' => $sub, 'cache' => 'invalidated']);
    }

    // ---- Service-Token -------------------------------------------------------------------------------------

    /** Rotiert beide Service-Token; die neuen Werte kommen versiegelt (Sealed Box an Dash) zurueck. */
    public function serviceTokenRotate(ServiceTokens $tokens, Request $r): JsonResponse
    {
        try {
            $res = $tokens->rotate((string) $r->attributes->get('machine_installation'));
        } catch (\InvalidArgumentException) {
            return ApiError::response('validation_failed', 'Dash X25519 key is not registered', ['reason' => 'dash_box_key_missing']);
        }

        return ApiError::data(['sealed_tokens' => $res['sealed'], 'previous_token_grace_seconds' => $res['grace_seconds']]);
    }
}
