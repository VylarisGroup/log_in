<?php

namespace App\Http\Middleware;

use App\Models\Audit;
use App\Models\Setting;
use App\Services\Vylaris\Signer;
use Closure;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authentifiziert eingehende Dash-Aufrufe (/api/dash/v1/*): Ed25519-Signatur ueber Methode, Pfad, Zeitstempel,
 * Nonce und Body-Hash; Replay-Schutz ueber einmalig verwendbare Nonces; signierte Antworten.
 */
class VerifyDashSignature
{
    public function handle(Request $request, Closure $next): Response
    {
        $pub = Setting::get('dash.public_key');
        $dashId = Setting::get('dash.installation_id');
        $secret = Setting::get('login.sign_secret');
        if ($pub === null || $dashId === null || $secret === null) {
            return $this->deny('dash_not_configured', 503);
        }

        $keyId = (string) $request->header('X-Vylaris-Key-Id');
        $ts = (string) $request->header('X-Vylaris-Timestamp');
        $nonce = (string) $request->header('X-Vylaris-Nonce');
        $sig = (string) $request->header('X-Vylaris-Signature');

        if (! hash_equals($dashId, $keyId) || ! ctype_digit($ts) || ! preg_match('/^[A-Za-z0-9_\-]{16,64}$/', $nonce) || $sig === '') {
            return $this->deny('bad_auth_headers');
        }
        if (abs(time() - (int) $ts) > (int) config('vylaris.dash.clock_skew')) {
            return $this->deny('timestamp_out_of_range');
        }

        $body = $request->getContent();
        $canonical = Signer::requestCanonical($request->method(), $request->getRequestUri(), (int) $ts, $nonce, $body);
        if (! Signer::verify($canonical, $sig, $pub)) {
            Audit::log('api.signature_invalid', 'dash', null, ['path' => $request->path()]);

            return $this->deny('bad_signature');
        }

        DB::table('api_nonces')->where('expires_at', '<', now())->delete();
        try {
            DB::table('api_nonces')->insert(['nonce' => $nonce, 'key_id' => $keyId, 'expires_at' => now()->addSeconds((int) config('vylaris.dash.nonce_ttl'))]);
        } catch (QueryException $e) {
            Audit::log('api.replay_blocked', 'dash', null, ['path' => $request->path()]);

            return $this->deny('replay');
        }

        $response = $next($request);

        // Antwort signieren, gebunden an die Nonce der Anfrage.
        $rts = time();
        $response->headers->set('X-Vylaris-Timestamp', (string) $rts);
        $response->headers->set('X-Vylaris-Signature', Signer::sign(Signer::responseCanonical($response->getStatusCode(), $nonce, $rts, (string) $response->getContent()), Setting::getSecret('login.sign_secret')));
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    private function deny(string $code, int $status = 401): Response
    {
        return response()->json(['error' => $code], $status);
    }
}
