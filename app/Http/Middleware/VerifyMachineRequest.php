<?php

namespace App\Http\Middleware;

use App\Models\Audit;
use App\Models\ServiceToken;
use App\Models\Setting;
use App\Services\Vylaris\ServiceTokens;
use App\Services\Vylaris\Signer;
use App\Support\ApiError;
use Closure;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authentifiziert Maschinenrequests von Dash: Bearer-Service-Token (Installation, Scope, Ablauf, Widerruf) UND
 * Ed25519-Signatur (Methode, Pfad, Zeitstempel, Nonce, Body-Hash) mit Replay-Schutz. Antworten werden signiert.
 * Verwendung: vylaris.machine:<scope>
 */
class VerifyMachineRequest
{
    public function __construct(private readonly ServiceTokens $tokens) {}

    public function handle(Request $request, Closure $next, string $scope): Response
    {
        $pub = Setting::get('dash.public_key');
        $dashId = Setting::get('dash.installation_id');
        $secret = Setting::get('login.sign_secret');
        if ($pub === null || $dashId === null || $secret === null) {
            return ApiError::response('service_unavailable');
        }

        $bearer = $request->bearerToken();
        if ($bearer === null || $bearer === '') {
            return ApiError::response('unauthorized');
        }
        $keyId = (string) $request->header('X-Vylaris-Key-Id');
        $ts = (string) $request->header('X-Vylaris-Timestamp');
        $nonce = (string) $request->header('X-Vylaris-Nonce');
        $sig = (string) $request->header('X-Vylaris-Signature');
        if (! hash_equals($dashId, $keyId)) {
            return ApiError::response('unauthorized');
        }

        $token = ServiceToken::query()->where('token_hash', ServiceTokens::hash($bearer))->first();
        if ($token === null || ! hash_equals($token->installation_id, $keyId)) {
            return ApiError::response('invalid_token');
        }
        if ($token->status !== 'active') {
            return $token->revoked_reason === 'installation_revoked' ? ApiError::response('installation_revoked') : ApiError::response('invalid_token');
        }
        if ($token->expires_at->isPast()) {
            return ApiError::response('token_expired');
        }

        if (! ctype_digit($ts) || ! preg_match('/^[A-Za-z0-9_\-]{16,64}$/', $nonce) || $sig === '') {
            return ApiError::response('invalid_signature');
        }
        if (abs(time() - (int) $ts) > (int) config('vylaris.dash.clock_skew')) {
            return ApiError::response('timestamp_out_of_range');
        }

        $canonical = Signer::requestCanonical($request->method(), $request->getRequestUri(), (int) $ts, $nonce, $request->getContent());
        if (! Signer::verify($canonical, $sig, $pub)) {
            Audit::log('api.signature_invalid', 'dash', null, ['path' => $request->path()]);

            return ApiError::response('invalid_signature');
        }

        DB::table('api_nonces')->where('expires_at', '<', now())->delete();
        try {
            DB::table('api_nonces')->insert(['nonce' => $nonce, 'key_id' => $keyId, 'expires_at' => now()->addSeconds((int) config('vylaris.dash.nonce_ttl'))]);
        } catch (QueryException) {
            Audit::log('api.replay_blocked', 'dash', null, ['path' => $request->path()]);

            return ApiError::response('replay_detected');
        }

        if (! in_array($scope, $token->scopes, true)) {
            Audit::log('api.forbidden', 'dash', null, ['path' => $request->path(), 'scope' => $scope]);

            return $this->signed(ApiError::response('forbidden'), $nonce);
        }
        if ($token->activated_at === null) {
            $this->tokens->activate($token);
        }
        $token->forceFill(['last_used_at' => now()])->save();
        $request->attributes->set('machine_installation', $keyId);

        try {
            $response = $next($request);
        } catch (\Throwable $e) {
            $handler = app(ExceptionHandler::class);
            $handler->report($e);
            $response = $handler->render($request, $e);
        }

        return $this->signed($response, $nonce);
    }

    /** Antwort signieren, gebunden an die Nonce der Anfrage. */
    private function signed(Response $response, string $nonce): Response
    {
        $ts = time();
        $response->headers->set('X-Vylaris-Key-Id', (string) Setting::get('login.installation_id'));
        $response->headers->set('X-Vylaris-Timestamp', (string) $ts);
        $response->headers->set('X-Vylaris-Signature', Signer::sign(Signer::responseCanonical($response->getStatusCode(), $nonce, $ts, (string) $response->getContent()), (string) Setting::getSecret('login.sign_secret')));
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
