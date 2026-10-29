<?php

namespace App\Support;

use Illuminate\Http\JsonResponse;

/**
 * Einheitlicher Fehlervertrag der Vylaris-API: {"error":{"code","message","details"?}}.
 * Die Codes sind projektuebergreifend identisch (siehe docs/openapi.yaml).
 */
final class ApiError
{
    /** @var array<string, array{0: int, 1: string}> code => [HTTP-Status, Standardtext] */
    public const CODES = [
        'unauthorized' => [401, 'Authentication required'],
        'invalid_token' => [401, 'Bearer token is invalid'],
        'token_expired' => [401, 'Bearer token has expired'],
        'invalid_signature' => [401, 'Request signature is invalid'],
        'timestamp_out_of_range' => [401, 'Request timestamp is outside the accepted window'],
        'replay_detected' => [401, 'Request nonce was already used'],
        'forbidden' => [403, 'Operation is not permitted'],
        'pairing_closed' => [409, 'Pairing is closed or in a state that does not allow this operation'],
        'pairing_expired' => [410, 'Pairing window has expired'],
        'pairing_denied' => [403, 'Pairing was rejected'],
        'invalid_pairing_proof' => [422, 'Pairing proof is invalid'],
        'installation_revoked' => [403, 'Installation has been revoked'],
        'resource_not_found' => [404, 'Resource not found'],
        'duplicate_conflict' => [409, 'Resource already exists or conflicts with an existing one'],
        'idempotency_conflict' => [409, 'Idempotency-Key was used with a different request or is still in progress'],
        'validation_failed' => [422, 'Request validation failed'],
        'rate_limited' => [429, 'Too many requests'],
        'service_unavailable' => [503, 'Service is not available'],
        'internal_error' => [500, 'Internal error'],
    ];

    /**
     * @param  array<string, mixed>|list<string>  $details
     */
    public static function response(string $code, ?string $message = null, array $details = [], ?int $status = null): JsonResponse
    {
        [$defaultStatus, $defaultMessage] = self::CODES[$code] ?? self::CODES['internal_error'];
        $error = ['code' => isset(self::CODES[$code]) ? $code : 'internal_error', 'message' => $message ?? $defaultMessage];
        if ($details !== []) {
            $error['details'] = $details;
        }

        return response()->json(['error' => $error], $status ?? $defaultStatus);
    }

    /** @param  array<string, mixed>|list<mixed>  $data */
    public static function data(array $data, int $status = 200, ?array $meta = null): JsonResponse
    {
        $body = ['data' => $data];
        if ($meta !== null) {
            $body['meta'] = $meta;
        }

        return response()->json($body, $status);
    }
}
