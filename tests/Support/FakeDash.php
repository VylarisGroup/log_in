<?php

namespace Tests\Support;

use App\Models\OidcClient;
use App\Models\Setting;
use App\Services\Vylaris\ServiceTokens;
use App\Services\Vylaris\Signer;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request as HttpRequest;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Testing\TestResponse;

/**
 * Simuliert Dash fuer Tests: verifiziert die Signatur jedes log_in-Aufrufs, signiert Antworten mit dem Dash-Schluessel
 * und bildet Benutzer, Zugangsdaten, Mandanten, Rollen sowie Ausfaelle ab.
 */
trait FakeDash
{
    /** @var array{public: string, secret: string} */
    protected array $dashKeys;

    /** @var array{public: string, secret: string} */
    protected array $loginKeys;

    protected bool $dashDown = false;

    protected ?string $dashSignSecret = null;

    protected bool $dashUnsigned = false;

    protected int $dashCalls = 0;

    /** @var array<string, array<string, mixed>> */
    protected array $dashUsers = [];

    /** @var array<string, array{password: string, sub: string, mfa?: string}> */
    protected array $dashCreds = [];

    protected array $seenNonces = [];

    /** Plaintext des Dash->log_in Service-Tokens (Bearer, den Dash sendet). */
    protected string $dashToken = '';

    /** Das log_in->Dash Token, das Dash als gueltig akzeptiert. */
    protected string $dashOutboundToken = '';

    /** @var array{public: string, secret: string} X25519 von Dash (fuer versiegelte Token-Rotation) */
    protected array $dashBox;

    protected function bootFakeDash(): void
    {
        $this->dashKeys = Signer::generateKeypair();
        $this->loginKeys = Signer::generateKeypair();
        $this->dashBox = Signer::generateBoxKeypair();
        Setting::put('dash.base_url', 'https://dash.test');
        Setting::put('dash.installation_id', 'dash-install-0001');
        Setting::put('dash.public_key', $this->dashKeys['public']);
        Setting::put('dash.box_public_key', $this->dashBox['public']);
        Setting::put('login.installation_id', 'login-install-0001');
        Setting::put('login.sign_public', $this->loginKeys['public']);
        Setting::putSecret('login.sign_secret', $this->loginKeys['secret']);
        config(['vylaris.issuer' => 'https://login.test', 'app.url' => 'https://login.test']);

        [$this->dashToken] = app(ServiceTokens::class)->bootstrap('dash-install-0001');
        $this->dashOutboundToken = (string) Setting::getSecret('dash.outbound_token');

        $this->dashUsers = [
            'u-alice' => ['sub' => 'u-alice', 'status' => 'active', 'name' => 'Alice', 'email' => 'alice@example.test', 'email_verified' => true, 'tenant_id' => 't-1', 'roles' => ['admin']],
            'u-bob' => ['sub' => 'u-bob', 'status' => 'active', 'name' => 'Bob', 'email' => 'bob@example.test', 'email_verified' => true, 'tenant_id' => 't-2', 'roles' => ['member']],
        ];
        $this->dashCreds = [
            'alice@example.test' => ['password' => 'correct-horse-battery', 'sub' => 'u-alice'],
            'bob@example.test' => ['password' => 'bobs-long-password-1', 'sub' => 'u-bob'],
        ];

        Http::fake(fn (HttpRequest $req) => $this->handleDash($req));
    }

    private function handleDash(HttpRequest $req)
    {
        $this->dashCalls++;
        if ($this->dashDown) {
            throw new ConnectionException('dash down');
        }
        $path = parse_url($req->url(), PHP_URL_PATH);
        if ($path === '/.well-known/vylaris-dash') {
            return Http::response(['api_version' => 'v1', 'installation_id' => 'dash-install-0001', 'name' => 'Dash', 'public_key' => $this->dashKeys['public'], 'box_public_key' => $this->dashBox['public']], 200);
        }
        $h = fn (string $n) => $req->header($n)[0] ?? '';
        if ($h('Authorization') !== 'Bearer '.$this->dashOutboundToken) {
            return $this->signedDash(401, ['error' => ['code' => 'invalid_token', 'message' => 'Bearer token is invalid']], $h('X-Vylaris-Nonce'));
        }
        $canon = Signer::requestCanonical($req->method(), $path, (int) $h('X-Vylaris-Timestamp'), $h('X-Vylaris-Nonce'), (string) $req->body());
        if (! Signer::verify($canon, $h('X-Vylaris-Signature'), $this->loginKeys['public'])) {
            return $this->signedDash(401, ['error' => ['code' => 'invalid_signature', 'message' => 'x']], $h('X-Vylaris-Nonce'));
        }
        if (in_array($h('X-Vylaris-Nonce'), $this->seenNonces, true)) {
            return $this->signedDash(401, ['error' => ['code' => 'replay_detected', 'message' => 'x']], $h('X-Vylaris-Nonce'));
        }
        $this->seenNonces[] = $h('X-Vylaris-Nonce');
        $n = $h('X-Vylaris-Nonce');

        if ($path === '/api/vylaris/v1/health') {
            return $this->signedDash(200, ['status' => 'ok'], $n);
        }
        if ($path === '/api/vylaris/v1/auth/credentials/verify') {
            $b = json_decode((string) $req->body(), true);
            $c = $this->dashCreds[mb_strtolower($b['identifier'])] ?? null;
            if ($c === null || ! hash_equals($c['password'], $b['password'])) {
                return $this->signedDash(200, ['result' => 'invalid'], $n);
            }
            if (($this->dashUsers[$c['sub']]['status'] ?? '') === 'locked') {
                return $this->signedDash(200, ['result' => 'locked'], $n);
            }
            if (isset($c['mfa'])) {
                if (empty($b['mfa_code'])) {
                    return $this->signedDash(200, ['result' => 'mfa_required'], $n);
                }
                if ($b['mfa_code'] !== $c['mfa']) {
                    return $this->signedDash(200, ['result' => 'invalid'], $n);
                }

                return $this->signedDash(200, ['result' => 'ok', 'sub' => $c['sub'], 'amr' => ['pwd', 'otp']], $n);
            }

            return $this->signedDash(200, ['result' => 'ok', 'sub' => $c['sub'], 'amr' => ['pwd']], $n);
        }
        if (preg_match('#^/api/vylaris/v1/users/(.+)$#', $path, $m)) {
            $sub = rawurldecode($m[1]);
            if (! isset($this->dashUsers[$sub])) {
                return $this->signedDash(404, ['error' => 'not_found'], $n);
            }

            return $this->signedDash(200, $this->dashUsers[$sub], $n);
        }

        return $this->signedDash(404, ['error' => 'unknown'], $n);
    }

    protected function signedDash(int $status, array $body, string $requestNonce, ?string $secret = null)
    {
        if ($status < 300) {
            $body = ['data' => $body];
        } elseif (isset($body['error']) && is_string($body['error'])) {
            $body = ['error' => ['code' => 'resource_not_found', 'message' => $body['error']]];
        }
        $json = json_encode($body);
        if ($this->dashUnsigned) {
            return Http::response($json, $status, ['Content-Type' => 'application/json']);
        }
        $ts = time();
        $sig = Signer::sign(Signer::responseCanonical($status, $requestNonce, $ts, $json), $secret ?? $this->dashSignSecret ?? $this->dashKeys['secret']);

        return Http::response($json, $status, ['Content-Type' => 'application/json', 'X-Vylaris-Timestamp' => (string) $ts, 'X-Vylaris-Signature' => $sig, 'X-Vylaris-Key-Id' => 'dash-install-0001']);
    }

    /** Signierter Aufruf von Dash gegen log_in (Dash -> log_in). */
    protected function dashApi(string $method, string $path, ?array $body = null, array $override = []): TestResponse
    {
        $json = $body === null ? '' : json_encode($body);
        $ts = $override['ts'] ?? time();
        $nonce = $override['nonce'] ?? Signer::randomNonce();
        $sig = $override['sig'] ?? Signer::sign(Signer::requestCanonical($method, $path, $ts, $nonce, $json), $override['secret'] ?? $this->dashKeys['secret']);
        $server = [
            'HTTP_X_VYLARIS_KEY_ID' => $override['key_id'] ?? 'dash-install-0001',
            'HTTP_X_VYLARIS_TIMESTAMP' => (string) $ts,
            'HTTP_X_VYLARIS_NONCE' => $nonce,
            'HTTP_X_VYLARIS_SIGNATURE' => $sig,
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
        ];
        $token = array_key_exists('token', $override) ? $override['token'] : $this->dashToken;
        if ($token !== null) {
            $server['HTTP_AUTHORIZATION'] = 'Bearer '.$token;
        }
        if (isset($override['idempotency'])) {
            $server['HTTP_IDEMPOTENCY_KEY'] = $override['idempotency'];
        }
        $this->lastDashNonce = $nonce;

        return $this->call($method, $path, [], [], [], $server, $json);
    }

    protected ?string $lastDashNonce = null;

    protected function makeClient(array $attrs = []): array
    {
        $secret = 'test-secret-'.bin2hex(random_bytes(8));
        $c = OidcClient::query()->create(array_merge([
            'client_id' => 'vl_test_client',
            'installation_id' => 'tool-install-0001',
            'name' => 'Testtool',
            'domain' => 'tool.test',
            'confidential' => true,
            'secret_hash' => OidcClient::hashSecret($secret),
            'redirect_uris' => ['https://tool.test/callback'],
            'post_logout_uris' => ['https://tool.test/bye'],
            'scopes' => ['openid', 'profile', 'email', 'vylaris', 'offline_access'],
            'status' => 'active',
        ], $attrs));

        return [$c, $secret];
    }

    protected function pkce(): array
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');

        return [$verifier, rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=')];
    }

    /** Fuehrt Login + Authorize durch und liefert Code, State und Nonce. */
    protected function loginAndAuthorize(OidcClient $c, string $email = 'alice@example.test', string $password = 'correct-horse-battery', array $extra = []): array
    {
        [$verifier, $challenge] = $this->pkce();
        $params = array_merge([
            'response_type' => 'code',
            'client_id' => $c->client_id,
            'redirect_uri' => $c->redirect_uris[0],
            'scope' => 'openid profile email vylaris offline_access',
            'state' => 'st-'.bin2hex(random_bytes(6)),
            'nonce' => 'no-'.bin2hex(random_bytes(6)),
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ], $extra);
        $url = '/authorize?'.http_build_query($params);
        $r = $this->get($url);
        if ($r->headers->get('Location') === url('/login')) {
            $this->post('/login', ['identifier' => $email, 'password' => $password])->assertRedirect();
            $r = $this->get($url);
        }
        $loc = $r->headers->get('Location');
        parse_str((string) parse_url($loc, PHP_URL_QUERY), $q);

        return ['location' => $loc, 'query' => $q, 'verifier' => $verifier, 'params' => $params, 'url' => $url];
    }

    protected function exchange(OidcClient $c, string $secret, string $code, string $verifier, array $extra = [])
    {
        return $this->post('/token', array_merge([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $c->redirect_uris[0],
            'code_verifier' => $verifier,
        ], $extra), ['Authorization' => 'Basic '.base64_encode($c->client_id.':'.$secret)]);
    }

    protected function clearCaches(): void
    {
        Cache::flush();
    }
}
