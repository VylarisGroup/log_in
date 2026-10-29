<?php

namespace App\Http\Controllers\Setup;

use App\Http\Controllers\Controller;
use App\Http\Middleware\EnsureInstalled;
use App\Models\Audit;
use App\Models\BootstrapAdmin;
use App\Models\Setting;
use App\Services\Vylaris\SetupService;
use App\Services\Vylaris\Totp;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\View\View;

/** Gefuehrter Erstsetup-Assistent und eng begrenzter Wartungszugang (siehe docs/BOOTSTRAP.md). */
class SetupController extends Controller
{
    public function __construct(private readonly SetupService $setup) {}

    private function allowed(Request $r): bool
    {
        $s = $r->session();
        if (! $this->setup->isCompleted()) {
            return (int) $s->get('setup_ok', 0) > time() - 3600;
        }

        return (bool) $s->get('setup_recovery') || $this->maintenanceAdmin($r) !== null;
    }

    /** Statt einer nackten 403-Seite: zurueck zum Token-Formular mit Erklaerung (Sitzung abgelaufen/verloren). */
    private function requireSetup(Request $r, bool $notCompleted = false): void
    {
        if ($this->allowed($r) && (! $notCompleted || ! $this->setup->isCompleted())) {
            return;
        }
        abort_if($this->setup->isCompleted(), 403); // abgeschlossenes Setup bleibt hart gesperrt
        Log::warning('setup: Zugriff ohne gueltige Setup-Sitzung', ['path' => $r->path(), 'has_session_cookie' => $r->hasCookie(config('session.cookie'))]);

        throw new HttpResponseException(redirect()->route('setup.index')->with('error', 'Die Setup-Sitzung ist abgelaufen oder wurde nicht gespeichert (Cookies aktiv? Seite ueber HTTPS?). Bitte das Setup-Token erneut eingeben.'));
    }

    private function maintenanceAdmin(Request $r): ?BootstrapAdmin
    {
        $id = $r->session()->get('setup_admin_id');
        $a = $id ? BootstrapAdmin::query()->find($id) : null;

        return $a !== null && $a->isUsable() ? $a : null;
    }

    public function index(Request $r): View|RedirectResponse
    {
        if (! $this->setup->isCompleted()) {
            $this->setup->ensureToken();
        }
        if (! $this->allowed($r)) {
            return view('setup.gate', ['completed' => $this->setup->isCompleted(), 'tokenPath' => $this->setup->tokenPath()]);
        }
        $totp = $r->session()->get('setup_totp');
        if (Setting::get('setup.admin_done') !== '1' && $totp === null) {
            $totp = Totp::newSecret();
            $r->session()->put('setup_totp', $totp);
        }

        return view('setup.wizard', [
            'completed' => $this->setup->isCompleted(),
            'mode' => $this->setup->mode(),
            'env' => $this->setup->environment(),
            'adminDone' => Setting::get('setup.admin_done') === '1',
            'keysDone' => Setting::get('setup.keys_done') === '1',
            'dashDone' => Setting::get('setup.dash_done') === '1',
            'clientDone' => Setting::get('setup.client_done') === '1',
            'testOk' => Setting::get('setup.test_ok') === '1',
            'totpSecret' => $totp,
            'totpUri' => $totp ? Totp::uri($totp, 'setup-admin') : null,
            'dashBase' => Setting::get('dash.base_url'),
            'discovered' => $r->session()->get('setup_discovered'),
            'bundleReady' => is_file($this->setup->bundlePath()),
            'installed' => EnsureInstalled::installed(),
            'issuer' => config('vylaris.issuer'),
            'dbMode' => config('database.default'),
            'registerError' => session('register_error'),
            'checks' => session('setup_checks'),
        ]);
    }

    public function token(Request $r): RedirectResponse
    {
        $key = 'setup-token:'.$r->ip();
        if ($this->setup->isCompleted() || RateLimiter::tooManyAttempts($key, 5)) {
            return back()->withErrors(['token' => 'Nicht verfuegbar.']);
        }
        if (! $this->setup->checkToken((string) $r->input('token'))) {
            RateLimiter::hit($key, 900);
            Audit::log('setup.token_failed');

            return back()->withErrors(['token' => 'Token ungueltig.']);
        }
        RateLimiter::clear($key);
        $r->session()->regenerate();
        $r->session()->put('setup_ok', time());

        return redirect()->route('setup.index');
    }

    /** Ein-Klick-Installation: Adresse, Datenbank, Migrationen, Schluessel, Setup-Admin. */
    public function install(Request $r): RedirectResponse
    {
        $this->requireSetup($r, true);
        $d = $r->validate([
            'issuer' => 'nullable|string|max:255', 'db_mode' => 'nullable|in:sqlite,mysql',
            'db_host' => 'nullable|string|max:255', 'db_port' => 'nullable|string|max:6', 'db_name' => 'nullable|string|max:64',
            'db_user' => 'nullable|string|max:64', 'db_password' => 'nullable|string|max:200',
            'username' => 'required|string|max:40', 'password' => 'required|string|max:200', 'password_confirmation' => 'required|same:password', 'totp_code' => 'required|string|max:10',
        ]);
        try {
            $this->setup->install($d, (string) $r->session()->get('setup_totp'));
        } catch (\InvalidArgumentException $e) {
            return back()->withErrors(['install' => $e->getMessage()])->withInput($r->except(['password', 'password_confirmation', 'db_password']));
        }
        $r->session()->forget('setup_totp');

        return redirect()->route('setup.index');
    }

    /** Download des Bootstrap-Bundles (enthaelt Geheimnisse; nur fuer die berechtigte Setup-Sitzung). */
    public function bundle(Request $r)
    {
        abort_unless($this->allowed($r) && is_file($this->setup->bundlePath()), 404);
        Audit::log('setup.bundle_downloaded', 'setup');

        return response()->download($this->setup->bundlePath(), 'dash-bootstrap.json', ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
    }

    public function admin(Request $r): RedirectResponse
    {
        $this->requireSetup($r, true);
        $d = $r->validate(['username' => 'required|string|max:40', 'password' => 'required|string|max:200', 'password_confirmation' => 'required|same:password', 'totp_code' => 'required|string|max:10']);
        try {
            $this->setup->createAdmin($d['username'], $d['password'], (string) $r->session()->get('setup_totp'), $d['totp_code']);
        } catch (\InvalidArgumentException $e) {
            return back()->withErrors(['admin' => $e->getMessage()]);
        }
        $r->session()->forget('setup_totp');

        return redirect()->route('setup.index');
    }

    public function keys(Request $r): RedirectResponse
    {
        $this->requireSetup($r);
        $this->setup->generateKeys();

        return redirect()->route('setup.index');
    }

    public function discover(Request $r): RedirectResponse
    {
        $this->requireSetup($r);
        // Auch "dash.example.ch" ohne Schema ist erlaubt (manche Webhoster-Firewalls blockieren URLs in Formularfeldern)
        $url = trim((string) $r->input('dash_url'));
        $r->merge(['dash_url' => preg_match('#^[a-z][a-z0-9+.-]*://#i', $url) ? $url : 'https://'.$url]);
        $r->validate(['dash_url' => 'required|url|max:255']);
        try {
            $r->session()->put('setup_discovered', $this->setup->discoverDash((string) $r->input('dash_url')));
        } catch (\Throwable $e) {
            return back()->withErrors(['dash' => 'Dash nicht gefunden: '.$e->getMessage()])->withInput();
        }

        return redirect()->route('setup.index');
    }

    public function trust(Request $r): RedirectResponse
    {
        $this->requireSetup($r);
        $d = $r->session()->get('setup_discovered');
        if (! is_array($d)) {
            return redirect()->route('setup.index');
        }
        try {
            $trusted = $this->setup->trustDash($d['base_url'], (string) $r->input('fingerprint'));
        } catch (\Throwable $e) {
            return back()->withErrors(['dash' => $e->getMessage()]);
        }
        $r->session()->forget('setup_discovered');
        // Dash direkt als OIDC-Anwendung anmelden (Standard-URIs bzw. Hinweise aus der Discovery)
        try {
            [$redirects, $logouts] = $this->setup->defaultDashUris($trusted);
            $r->session()->put('setup_bundle', $this->setup->registerDash($redirects, $logouts)['client_id']);
        } catch (\Throwable $e) {
            return redirect()->route('setup.index')->with('register_error', 'Automatische Registrierung nicht moeglich: '.$e->getMessage());
        }

        return redirect()->route('setup.index');
    }

    public function client(Request $r): RedirectResponse
    {
        $this->requireSetup($r);
        $split = fn (?string $v) => array_values(array_filter(array_map('trim', preg_split('/\R/', (string) $v))));
        try {
            $bundle = $this->setup->registerDash($split($r->input('redirect_uris')), $split($r->input('post_logout_uris')));
        } catch (\Throwable $e) {
            return back()->withErrors(['client' => $e->getMessage()])->withInput();
        }
        $r->session()->put('setup_bundle', $bundle['client_id']);

        return redirect()->route('setup.index');
    }

    public function test(Request $r): RedirectResponse
    {
        $this->requireSetup($r);
        $res = $this->setup->testConnection();

        return redirect()->route('setup.index')->with($res['ok'] ? 'status' : 'error', $res['message']);
    }

    public function finish(Request $r): RedirectResponse
    {
        $this->requireSetup($r, true);
        $ok = $this->setup->finish();
        if (! $ok) {
            return redirect()->route('setup.index')->with('setup_checks', $this->setup->integrityChecks())->with('error', 'Nicht alle Pruefungen bestanden.');
        }
        $r->session()->forget('setup_ok');

        return redirect()->route('setup.index')->with('status', 'Setup abgeschlossen. Dash kann sich jetzt ueber OIDC anmelden; danach endet der Bootstrap automatisch.');
    }

    public function loginForm(): View
    {
        return view('setup.login');
    }

    /** Eng begrenzter Wartungszugang des Setup-Admins (laeuft ab, endet mit Dash-Aktivierung). */
    public function login(Request $r): RedirectResponse
    {
        $key = 'setup-login:'.$r->ip();
        if (RateLimiter::tooManyAttempts($key, 5)) {
            return back()->withErrors(['login' => 'Zu viele Versuche.']);
        }
        $a = BootstrapAdmin::query()->where('username', (string) $r->input('username'))->first();
        $ok = $a !== null && $a->isUsable() && ($a->locked_until === null || $a->locked_until->isPast())
            && Hash::check((string) $r->input('password'), $a->password_hash)
            && Totp::verify(Crypt::decryptString($a->totp_secret_enc), (string) $r->input('totp_code'));
        if (! $ok) {
            RateLimiter::hit($key, 900);
            if ($a !== null) {
                $a->increment('failed_attempts');
                if ($a->failed_attempts >= 5) {
                    $a->update(['locked_until' => now()->addMinutes(15), 'failed_attempts' => 0]);
                }
            }
            Audit::log('setup.login_failed');

            return back()->withErrors(['login' => 'Anmeldung fehlgeschlagen.']);
        }
        $a->update(['failed_attempts' => 0]);
        $r->session()->regenerate();
        $r->session()->put('setup_admin_id', $a->id);
        Audit::log('setup.login', $a->username);

        return redirect()->route('setup.index');
    }

    public function recover(Request $r, string $token): RedirectResponse
    {
        $key = 'setup-recover:'.$r->ip();
        if (RateLimiter::tooManyAttempts($key, 5) || ! $this->setup->consumeRecoveryToken($token)) {
            RateLimiter::hit($key, 900);
            abort(404);
        }
        $r->session()->regenerate();
        $r->session()->put('setup_recovery', true);

        return redirect()->route('setup.index');
    }
}
