<?php

namespace App\Http\Controllers\Oidc;

use App\Http\Controllers\Controller;
use App\Models\Audit;
use App\Models\OidcClient;
use App\Models\SsoSession;
use App\Services\Dash\DashClient;
use App\Services\Dash\DashUnavailableException;
use App\Services\Oidc\ClaimsBuilder;
use App\Services\Oidc\ClientRepository;
use App\Services\Oidc\KeyManager;
use App\Services\Oidc\OidcContext;
use App\Services\Oidc\ServerFactory;
use App\Services\Oidc\SsoSessions;
use App\Services\Oidc\TokenVerifier;
use App\Services\Oidc\UserEntity;
use App\Services\Vylaris\SetupService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

class OidcController extends Controller
{
    public function __construct(
        private readonly ServerFactory $factory,
        private readonly KeyManager $keys,
        private readonly SsoSessions $sessions,
        private readonly DashClient $dash,
        private readonly OidcContext $ctx,
        private readonly TokenVerifier $verifier,
    ) {}

    public function discovery(): JsonResponse
    {
        $i = config('vylaris.issuer');

        return response()->json([
            'issuer' => $i,
            'authorization_endpoint' => $i.'/authorize',
            'token_endpoint' => $i.'/token',
            'userinfo_endpoint' => $i.'/userinfo',
            'jwks_uri' => $i.'/.well-known/jwks.json',
            'end_session_endpoint' => $i.'/logout',
            'revocation_endpoint' => $i.'/revoke',
            'scopes_supported' => array_keys(config('vylaris.scopes')),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'code_challenge_methods_supported' => ['S256'],
            'claims_supported' => ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'sid', 'amr', 'azp', 'at_hash', 'name', 'email', 'email_verified', 'tenant_id', 'roles'],
            'prompt_values_supported' => ['none', 'login'],
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'claims_parameter_supported' => false,
        ])->header('Cache-Control', 'public, max-age=300');
    }

    public function jwks(): JsonResponse
    {
        return response()->json($this->keys->jwks())->header('Cache-Control', 'public, max-age=300');
    }

    public function authorizeEndpoint(Request $request): Response
    {
        $server = $this->factory->make();
        try {
            $ar = $server->validateAuthorizationRequest($this->psr($request));
        } catch (OAuthServerException $e) {
            return $this->oauthError($e);
        }

        $client = OidcClient::query()->findOrFail($ar->getClient()->getIdentifier());
        $redirect = $ar->getRedirectUri() ?? $client->redirect_uris[0];
        $state = (string) $request->query('state', '');
        $fail = fn (string $code, string $desc) => $this->redirectError($redirect, $code, $desc, $state);

        // Strikte Profile: nur Code-Flow mit state, nonce und PKCE S256, keine Request-Objekte.
        if ($request->query->has('request') || $request->query->has('request_uri')) {
            return $fail('request_not_supported', 'Request-Objekte werden nicht unterstuetzt');
        }
        if ($state === '' || strlen($state) > 512) {
            return $fail('invalid_request', 'state ist erforderlich');
        }
        $nonce = (string) $request->query('nonce', '');
        if ($nonce === '' || strlen($nonce) > 512) {
            return $fail('invalid_request', 'nonce ist erforderlich');
        }
        if ($ar->getCodeChallenge() === null || $ar->getCodeChallengeMethod() !== 'S256') {
            return $fail('invalid_request', 'PKCE mit S256 ist erforderlich');
        }
        $scopeIds = array_map(fn ($s) => $s->getIdentifier(), $ar->getScopes());
        if (! in_array('openid', $scopeIds, true)) {
            return $fail('invalid_scope', 'Scope openid ist erforderlich');
        }
        if (array_diff($scopeIds, $client->scopes) !== []) {
            return $fail('invalid_scope', 'Scope nicht fuer diesen Client registriert');
        }

        $prompt = (string) $request->query('prompt', '');
        $session = $this->sessions->valid($request->session()->get('sso_sid'), false);
        $maxAge = $request->query->has('max_age') && ctype_digit((string) $request->query('max_age')) ? (int) $request->query('max_age') : null;
        $mustReauth = $prompt === 'login' || ($session !== null && $maxAge !== null && $session->auth_time->diffInSeconds(now()) > $maxAge);
        $startedAt = $request->session()->get('login_started_at');
        if ($mustReauth && $session !== null && $startedAt !== null && $session->auth_time->getTimestamp() >= $startedAt) {
            $mustReauth = false; // frisch nach dem Login, Schleife vermeiden
        }

        if ($session === null || $mustReauth) {
            if ($prompt === 'none') {
                return $fail('login_required', 'Keine Sitzung');
            }
            $request->session()->put('pending_authorize', $request->getQueryString());
            $request->session()->put('login_started_at', time());

            return redirect()->route('login');
        }
        $this->sessions->valid($session->id); // Aktivitaet verbuchen

        try {
            $identity = $this->dash->identity($session->sub);
        } catch (DashUnavailableException) {
            return $fail('temporarily_unavailable', 'Identitaetsquelle voruebergehend nicht erreichbar');
        } catch (\Throwable) {
            return $fail('server_error', 'Identitaet nicht pruefbar');
        }
        if (! $identity->isActive()) {
            $this->sessions->revoke($session->id, 'account_inactive');
            Audit::log('authorize.denied_inactive', null, $session->sub, ['client' => $client->client_id]);

            return $fail('access_denied', 'Konto nicht aktiv');
        }

        $this->ctx->sid = $session->id;
        $this->ctx->nonce = $nonce;
        $this->ctx->authTime = $session->auth_time->getTimestamp();
        $this->ctx->amr = $session->amr ?? [];
        $ar->setUser(new UserEntity($session->sub));
        // Clients sind durch Dash-Pairing administrativ freigegeben; kein Endnutzer-Consent-Screen.
        $ar->setAuthorizationApproved(true);

        try {
            $psr = $server->completeAuthorizationRequest($ar, (new Psr17Factory)->createResponse());
        } catch (OAuthServerException $e) {
            return $this->oauthError($e);
        }
        Audit::log('authorize.code_issued', null, $session->sub, ['client' => $client->client_id]);

        return $this->toResponse($psr);
    }

    public function token(Request $request): Response
    {
        try {
            $psr = $this->factory->make()->respondToAccessTokenRequest($this->psr($request), (new Psr17Factory)->createResponse());
        } catch (OAuthServerException $e) {
            Audit::log('token.rejected', null, null, ['error' => $e->getErrorType(), 'client' => $request->input('client_id')]);

            return $this->oauthError($e);
        }

        if ($request->input('grant_type') === 'authorization_code' && OidcClient::query()->whereKey((string) $this->clientCredentials($request)[0] ?? '')->where('is_dash', true)->exists()) {
            // Erster erfolgreicher OIDC-Login von Dash: Bootstrap endet (Setup-Admin aus, Bundle weg).
            app(SetupService::class)->activateFromDash();
        }

        return $this->toResponse($psr);
    }

    public function userinfo(Request $request): Response
    {
        $auth = (string) $request->header('Authorization');
        if (! preg_match('/^Bearer ([A-Za-z0-9\-_=.]+)$/', $auth, $m)) {
            return $this->bearerError('invalid_request', 400);
        }
        $token = $this->verifier->verify($m[1]);
        if ($token === null) {
            return $this->bearerError('invalid_token', 401);
        }
        $jti = (string) $token->claims()->get('jti');
        $row = DB::table('oidc_access_tokens')->where('id', $jti)->first();
        $client = OidcClient::query()->find((string) $token->claims()->get('client_id'));
        if ($row === null || $row->revoked || $client === null || ! $client->isUsable()) {
            return $this->bearerError('invalid_token', 401);
        }
        if ($row->sid !== null && $this->sessions->valid($row->sid, false) === null) {
            return $this->bearerError('invalid_token', 401);
        }
        $scopes = explode(' ', (string) $token->claims()->get('scope'));
        if (! in_array('openid', $scopes, true)) {
            return $this->bearerError('insufficient_scope', 403);
        }
        try {
            $identity = $this->dash->identity((string) $row->user_id);
        } catch (DashUnavailableException) {
            return response()->json(['error' => 'temporarily_unavailable'], 503)->header('Cache-Control', 'no-store');
        } catch (\Throwable) {
            return $this->bearerError('invalid_token', 401);
        }
        if (! $identity->isActive()) {
            $this->sessions->revokeForUser((string) $row->user_id, 'account_inactive');

            return $this->bearerError('invalid_token', 401);
        }

        return response()->json(['sub' => $identity->sub] + ClaimsBuilder::forScopes($identity, $scopes))->header('Cache-Control', 'no-store')->header('Pragma', 'no-cache');
    }

    /** RFC 7009: antwortet immer 200, auch bei unbekanntem Token. */
    public function revoke(Request $request): Response
    {
        $creds = $this->clientCredentials($request);
        if ($creds === null || ! (new ClientRepository)->validateClient($creds[0], $creds[1], null)) {
            return response()->json(['error' => 'invalid_client'], 401)->header('WWW-Authenticate', 'Basic realm="log_in"');
        }
        $tok = (string) $request->input('token', '');
        if ($tok !== '') {
            $jwt = $this->verifier->verify($tok, false);
            if ($jwt !== null && $jwt->claims()->get('client_id') === $creds[0]) {
                DB::table('oidc_access_tokens')->where('id', $jwt->claims()->get('jti'))->update(['revoked' => true]);
            } else {
                $crypt = new class
                {
                    use CryptTrait;

                    public function open(string $s): ?object
                    {
                        $this->setEncryptionKey(ServerFactory::encryptionKey());
                        try {
                            return json_decode($this->decrypt($s)) ?: null;
                        } catch (\Throwable) {
                            return null;
                        }
                    }
                };
                $p = $crypt->open($tok);
                if ($p !== null && ($p->client_id ?? null) === $creds[0] && isset($p->refresh_token_id)) {
                    DB::table('oidc_refresh_tokens')->where('id', $p->refresh_token_id)->update(['revoked' => true]);
                    DB::table('oidc_access_tokens')->where('id', $p->access_token_id ?? '')->update(['revoked' => true]);
                }
            }
            Audit::log('token.revoked', $creds[0]);
        }

        return response('', 200)->header('Cache-Control', 'no-store');
    }

    /** RP-initiated Logout (OIDC RP-Initiated Logout 1.0). */
    public function logout(Request $request): Response
    {
        $hint = (string) $request->input('id_token_hint', '');
        $postLogout = (string) $request->input('post_logout_redirect_uri', '');
        $state = (string) $request->input('state', '');
        $token = $hint !== '' ? $this->verifier->verify($hint, false) : null;

        if ($token === null) {
            // Ohne gueltigen Hinweis nie automatisch weiterleiten oder abmelden (CSRF/Logout-Spam): Bestaetigungsseite.
            if ($request->isMethod('post') && $request->session()->token() === $request->input('_token')) {
                $this->endLocalSession($request);

                return response()->view('logged-out');
            }

            return response()->view('logout-confirm');
        }

        $aud = $token->claims()->get('aud')[0] ?? null;
        $client = OidcClient::query()->find($aud);
        $sess = SsoSession::query()->where('public_sid', (string) $token->claims()->get('sid'))->first();
        if ($sess !== null && $sess->sub === $token->claims()->get('sub')) {
            $this->sessions->revoke($sess->id, 'rp_logout');
        }
        $this->endLocalSession($request);
        Audit::log('logout.rp', $aud, (string) $token->claims()->get('sub'));

        if ($client !== null && $postLogout !== '' && in_array($postLogout, $client->post_logout_uris ?? [], true)) {
            $sep = str_contains($postLogout, '?') ? '&' : '?';

            return redirect()->away($postLogout.($state !== '' ? $sep.http_build_query(['state' => $state]) : ''));
        }

        return response()->view('logged-out');
    }

    private function endLocalSession(Request $request): void
    {
        $sid = $request->session()->get('sso_sid');
        if ($sid !== null) {
            $this->sessions->revoke($sid, 'logout');
        }
        $request->session()->invalidate();
        $request->session()->regenerateToken();
    }

    /** @return array{0: string, 1: ?string}|null */
    private function clientCredentials(Request $request): ?array
    {
        if (preg_match('/^Basic (.+)$/', (string) $request->header('Authorization'), $m)) {
            $d = base64_decode($m[1], true);
            if ($d !== false && str_contains($d, ':')) {
                [$id, $secret] = explode(':', $d, 2);

                return [rawurldecode($id), rawurldecode($secret)];
            }

            return null;
        }
        $id = $request->input('client_id');

        return is_string($id) && $id !== '' ? [$id, $request->input('client_secret')] : null;
    }

    private function psr(Request $request)
    {
        $f = new Psr17Factory;

        return (new PsrHttpFactory($f, $f, $f, $f))->createRequest($request);
    }

    private function toResponse($psr): Response
    {
        $r = (new HttpFoundationFactory)->createResponse($psr);
        $r->headers->set('Cache-Control', 'no-store');
        $r->headers->set('Pragma', 'no-cache');

        return $r;
    }

    private function oauthError(OAuthServerException $e): Response
    {
        return $this->toResponse($e->generateHttpResponse((new Psr17Factory)->createResponse()));
    }

    private function redirectError(string $redirect, string $error, string $desc, string $state): Response
    {
        $q = ['error' => $error, 'error_description' => $desc];
        if ($state !== '') {
            $q['state'] = $state;
        }
        $sep = str_contains($redirect, '?') ? '&' : '?';

        return redirect()->away($redirect.$sep.http_build_query($q));
    }

    private function bearerError(string $error, int $status): JsonResponse
    {
        return response()->json(['error' => $error], $status)->header('WWW-Authenticate', 'Bearer error="'.$error.'"')->header('Cache-Control', 'no-store');
    }
}
