<?php

namespace App\Services\Dash;

use App\Models\Setting;
use App\Services\Vylaris\ServiceTokens;
use App\Services\Vylaris\Signer;
use App\Services\Vylaris\SsrfGuard;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * Ausgehende Dash-API. Jede Anfrage ist mit dem Ed25519-Schluessel von log_in signiert
 * (Zeitstempel + Nonce), jede Antwort muss mit dem bei der Einrichtung bestaetigten Dash-Schluessel signiert sein.
 * Kein direkter Datenbankzugriff auf Dash.
 */
class DashClient
{
    private function prefix(): string
    {
        return (string) config('vylaris.api_prefix');
    }

    public function isConfigured(): bool
    {
        return Setting::get('dash.base_url') !== null && Setting::get('dash.public_key') !== null && Setting::get('login.installation_id') !== null;
    }

    public function baseUrl(): string
    {
        return rtrim((string) Setting::get('dash.base_url'), '/');
    }

    /** Oeffentliche, unsignierte Discovery. Der zurueckgegebene Schluessel ist erst nach Fingerprint-Bestaetigung vertrauenswuerdig. */
    public function discover(string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl, '/');
        $res = $this->http($baseUrl)->get($baseUrl.'/.well-known/vylaris-dash');
        if (! $res->ok()) {
            throw new DashUnavailableException('Dash-Discovery lieferte HTTP '.$res->status());
        }
        $d = $res->json();
        $d = is_array($d) && is_array($d['data'] ?? null) ? $d['data'] : $d; // Antwortvertrag: {"data": {...}}
        foreach (['api_version', 'installation_id', 'public_key', 'name'] as $k) {
            if (! is_array($d) || ! isset($d[$k]) || ! is_string($d[$k])) {
                throw new DashProtocolException("Discovery-Feld $k fehlt");
            }
        }
        if ($d['api_version'] !== config('vylaris.api_version') || strlen(base64_decode($d['public_key'], true) ?: '') !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new DashProtocolException('Nicht unterstuetzte API-Version oder ungueltiger Schluessel');
        }
        if (isset($d['box_public_key']) && (! is_string($d['box_public_key']) || strlen(base64_decode($d['box_public_key'], true) ?: '') !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES)) {
            throw new DashProtocolException('Ungueltiger X25519-Schluessel in der Discovery');
        }

        return $d;
    }

    /** @return array<string, mixed> */
    public function health(): array
    {
        return $this->signed('GET', '/health');
    }

    /**
     * Prueft Zugangsdaten bei Dash. Dash fuehrt Passwort- und MFA-Pruefung; log_in speichert nichts davon.
     *
     * @return array{result: string, sub?: string, amr?: list<string>}
     */
    public function verifyCredentials(string $identifier, string $password, ?string $mfaCode, ?string $clientIp): array
    {
        $r = $this->signed('POST', '/auth/credentials/verify', array_filter([
            'identifier' => $identifier,
            'password' => $password,
            'mfa_code' => $mfaCode,
            'client_ip' => $clientIp,
        ], fn ($v) => $v !== null));
        if (! in_array($r['result'] ?? null, ['ok', 'invalid', 'mfa_required', 'locked', 'disabled'], true)) {
            throw new DashProtocolException('Unbekanntes Ergebnis der Zugangsdatenpruefung');
        }
        if ($r['result'] === 'ok' && (! isset($r['sub']) || ! is_string($r['sub']) || $r['sub'] === '' || strlen($r['sub']) > 128)) {
            throw new DashProtocolException('Erfolgreiche Pruefung ohne gueltige Subject-ID');
        }

        return $r;
    }

    /**
     * Identitaet, Mandant und Rollen. Zwischenspeicher hoechstens claims_cache_ttl Sekunden;
     * $fresh = true umgeht ihn (Login, Refresh, Userinfo bei kritischen Pruefungen).
     */
    public function identity(string $sub, bool $fresh = false): DashIdentity
    {
        $key = 'dash.identity.'.hash('sha256', $sub);
        $ttl = (int) config('vylaris.dash.claims_cache_ttl');
        if (! $fresh && $ttl > 0 && is_array($c = Cache::get($key))) {
            return DashIdentity::fromArray($c, $sub);
        }
        $data = $this->signed('GET', '/users/'.rawurlencode($sub));
        $identity = DashIdentity::fromArray($data, $sub);
        if ($ttl > 0 && $identity->isActive()) {
            Cache::put($key, $data, $ttl);
        } else {
            Cache::forget($key);
        }

        return $identity;
    }

    public function forgetIdentity(string $sub): void
    {
        Cache::forget('dash.identity.'.hash('sha256', $sub));
    }

    /**
     * @param  array<string, mixed>|null  $body
     * @return array<string, mixed>
     */
    public function signed(string $method, string $path, ?array $body = null): array
    {
        if (! $this->isConfigured()) {
            throw new DashUnavailableException('Dash ist nicht eingerichtet');
        }
        $base = $this->baseUrl();
        $fullPath = $this->prefix().$path;
        $token = app(ServiceTokens::class)->outbound();
        if ($token === null) {
            throw new DashUnavailableException('Kein Service-Token fuer Dash vorhanden');
        }
        $json = $body === null ? '' : json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $ts = time();
        $nonce = Signer::randomNonce();
        $sig = Signer::sign(Signer::requestCanonical($method, $fullPath, $ts, $nonce, $json), (string) Setting::getSecret('login.sign_secret'));

        try {
            $req = $this->http($base)->withToken($token)->withHeaders([
                'X-Vylaris-Key-Id' => (string) Setting::get('login.installation_id'),
                'X-Vylaris-Timestamp' => (string) $ts,
                'X-Vylaris-Nonce' => $nonce,
                'X-Vylaris-Signature' => $sig,
                'Accept' => 'application/json',
            ]);
            $res = $json === ''
                ? $req->send($method, $base.$fullPath)
                : $req->withBody($json, 'application/json')->send($method, $base.$fullPath);
        } catch (ConnectionException $e) {
            throw new DashUnavailableException('Dash nicht erreichbar');
        }

        if ($res->serverError() || $res->status() === 429) {
            throw new DashUnavailableException('Dash meldet HTTP '.$res->status());
        }

        $this->verifyResponse($res->status(), (string) $res->body(), $nonce, (string) $res->header('X-Vylaris-Timestamp'), (string) $res->header('X-Vylaris-Signature'), (string) $res->header('X-Vylaris-Key-Id'));

        if ($res->status() === 404 || $res->status() === 410) { // resource_not_found
            // Unbekanntes oder geloeschtes Konto: wie "deleted" behandeln, nie als erfolgreich.
            return ['status' => 'deleted', 'sub' => rawurldecode(substr($path, strrpos($path, '/') + 1))];
        }
        if (! $res->successful()) {
            $code = is_array($res->json('error')) ? (string) $res->json('error.code') : '';
            throw new DashProtocolException('Dash lehnte die Anfrage ab (HTTP '.$res->status().($code !== '' ? ', '.$code : '').')');
        }
        $data = $res->json('data');
        if (! is_array($data)) {
            throw new DashProtocolException('Antwort enthaelt kein data-Objekt');
        }

        return $data;
    }

    private function verifyResponse(int $status, string $body, string $requestNonce, string $ts, string $sig, string $keyId): void
    {
        if (! hash_equals((string) Setting::get('dash.installation_id'), $keyId)) {
            throw new DashProtocolException('Antwort stammt nicht von der vertrauten Dash-Installation');
        }
        if ($ts === '' || $sig === '' || ! ctype_digit($ts)) {
            throw new DashProtocolException('Antwort ohne Signatur');
        }
        if (abs(time() - (int) $ts) > (int) config('vylaris.dash.clock_skew')) {
            throw new DashProtocolException('Antwort-Zeitstempel ausserhalb der Toleranz');
        }
        $pub = (string) Setting::get('dash.public_key');
        if (! Signer::verify(Signer::responseCanonical($status, $requestNonce, (int) $ts, $body), $sig, $pub)) {
            throw new DashProtocolException('Antwortsignatur ungueltig');
        }
    }

    /** Prueft die Zieladresse (SSRF-Schutz) und nagelt die geprueften IP fuer die Verbindung fest; Redirects sind aus. */
    private function http(string $url): PendingRequest
    {
        try {
            $t = SsrfGuard::check($url);
        } catch (\InvalidArgumentException $e) {
            throw new DashProtocolException('Dash-URL abgelehnt: '.$e->getMessage());
        }
        $opts = ['verify' => true];
        if ($t['ip'] !== null && defined('CURLOPT_RESOLVE')) {
            $opts['curl'] = [CURLOPT_RESOLVE => [$t['host'].':'.$t['port'].':'.$t['ip']]];
        }

        return Http::timeout((int) config('vylaris.dash.timeout'))
            ->connectTimeout((int) config('vylaris.dash.connect_timeout'))
            ->withoutRedirecting()
            ->withOptions($opts);
    }
}
