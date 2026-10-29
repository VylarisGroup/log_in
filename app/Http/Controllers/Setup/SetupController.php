<?php

namespace App\Http\Controllers\Setup;

use App\Http\Controllers\Controller;
use App\Models\Audit;
use App\Models\BootstrapAdmin;
use App\Models\Setting;
use App\Services\Vylaris\SetupService;
use App\Services\Vylaris\Totp;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
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
            'bundle' => $r->session()->pull('setup_bundle'),
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

    public function admin(Request $r): RedirectResponse
    {
        abort_unless($this->allowed($r) && ! $this->setup->isCompleted(), 403);
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
        abort_unless($this->allowed($r), 403);
        $this->setup->generateKeys();

        return redirect()->route('setup.index');
    }

    public function discover(Request $r): RedirectResponse
    {
        abort_unless($this->allowed($r), 403);
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
        abort_unless($this->allowed($r), 403);
        $d = $r->session()->get('setup_discovered');
        if (! is_array($d)) {
            return redirect()->route('setup.index');
        }
        try {
            $this->setup->trustDash($d['base_url'], (string) $r->input('fingerprint'));
        } catch (\Throwable $e) {
            return back()->withErrors(['dash' => $e->getMessage()]);
        }
        $r->session()->forget('setup_discovered');

        return redirect()->route('setup.index');
    }

    public function client(Request $r): RedirectResponse
    {
        abort_unless($this->allowed($r), 403);
        $split = fn (?string $v) => array_values(array_filter(array_map('trim', preg_split('/\R/', (string) $v))));
        try {
            $bundle = $this->setup->registerDash($split($r->input('redirect_uris')), $split($r->input('post_logout_uris')));
        } catch (\Throwable $e) {
            return back()->withErrors(['client' => $e->getMessage()])->withInput();
        }
        $r->session()->put('setup_bundle', $bundle);

        return redirect()->route('setup.index');
    }

    public function test(Request $r): RedirectResponse
    {
        abort_unless($this->allowed($r), 403);
        $res = $this->setup->testConnection();

        return redirect()->route('setup.index')->with($res['ok'] ? 'status' : 'error', $res['message']);
    }

    public function finish(Request $r): RedirectResponse
    {
        abort_unless($this->allowed($r) && ! $this->setup->isCompleted(), 403);
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
