<?php

namespace App\Http\Middleware;

use App\Support\ApiError;
use Closure;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

/**
 * Idempotenz fuer schreibende Maschinenrequests ueber den Header "Idempotency-Key".
 * Gleicher Schluessel + gleicher Request -> gespeicherte Antwort; gleicher Schluessel + anderer Request -> 409.
 * Muss innerhalb von VerifyMachineRequest laufen (Antwort wird dort frisch signiert).
 */
class EnforceIdempotency
{
    public function handle(Request $request, Closure $next): Response
    {
        $key = $request->header('Idempotency-Key');
        if ($key === null || in_array($request->method(), ['GET', 'HEAD', 'OPTIONS'], true)) {
            return $next($request);
        }
        if (! preg_match('/^[A-Za-z0-9_.:\-]{8,128}$/', (string) $key)) {
            return ApiError::response('validation_failed', 'Idempotency-Key must be 8-128 characters of [A-Za-z0-9_.:-]');
        }
        $inst = (string) $request->attributes->get('machine_installation');
        $hash = hash('sha256', $request->method()."\n".$request->getRequestUri()."\n".$request->getContent());

        DB::table('idempotency_keys')->where('expires_at', '<', now())->delete();
        try {
            DB::table('idempotency_keys')->insert([
                'installation_id' => $inst, 'idem_key' => $key, 'request_hash' => $hash,
                'expires_at' => now()->addHours((int) config('vylaris.idempotency_ttl_hours')), 'created_at' => now(), 'updated_at' => now(),
            ]);
        } catch (QueryException) {
            $row = DB::table('idempotency_keys')->where('installation_id', $inst)->where('idem_key', $key)->first();
            if ($row === null || ! hash_equals($row->request_hash, $hash) || $row->response_status === null) {
                return ApiError::response('idempotency_conflict');
            }

            return response($row->response_body, $row->response_status, ['Content-Type' => 'application/json', 'Idempotent-Replayed' => 'true']);
        }

        try {
            $response = $next($request);
        } catch (\Throwable $e) {
            DB::table('idempotency_keys')->where('installation_id', $inst)->where('idem_key', $key)->delete();
            throw $e;
        }
        if ($response->getStatusCode() >= 500) {
            DB::table('idempotency_keys')->where('installation_id', $inst)->where('idem_key', $key)->delete();
        } else {
            DB::table('idempotency_keys')->where('installation_id', $inst)->where('idem_key', $key)
                ->update(['response_status' => $response->getStatusCode(), 'response_body' => (string) $response->getContent(), 'updated_at' => now()]);
        }

        return $response;
    }
}
