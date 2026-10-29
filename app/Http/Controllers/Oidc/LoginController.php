<?php

namespace App\Http\Controllers\Oidc;

use App\Http\Controllers\Controller;
use App\Models\Audit;
use App\Services\Dash\DashClient;
use App\Services\Dash\DashUnavailableException;
use App\Services\Oidc\SsoSessions;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\View\View;

/**
 * Browser-Anmeldung. log_in speichert keine Passwoerter: Zugangsdaten werden ueber die signierte Dash-API geprueft.
 */
class LoginController extends Controller
{
    public function __construct(private readonly DashClient $dash, private readonly SsoSessions $sessions) {}

    public function show(Request $request): View|RedirectResponse
    {
        if (! $this->dash->isConfigured()) {
            return redirect()->route('setup.index');
        }

        return view('login', ['mfa' => (bool) $request->session()->get('mfa_required')]);
    }

    public function store(Request $request): RedirectResponse
    {
        if (! $this->dash->isConfigured()) {
            return redirect()->route('setup.index');
        }
        $data = $request->validate([
            'identifier' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'max:1024'],
            'mfa_code' => ['nullable', 'string', 'max:16'],
        ]);

        $keys = ['login-ip:'.$request->ip(), 'login-id:'.hash('sha256', mb_strtolower($data['identifier']))];
        foreach ($keys as $k) {
            if (RateLimiter::tooManyAttempts($k, 8)) {
                Audit::log('login.throttled', null, null);

                return back()->withErrors(['identifier' => 'Zu viele Versuche. Bitte spaeter erneut versuchen.'])->onlyInput('identifier');
            }
        }

        try {
            $r = $this->dash->verifyCredentials($data['identifier'], $data['password'], $data['mfa_code'] ?? null, $request->ip());
        } catch (DashUnavailableException) {
            return back()->withErrors(['identifier' => 'Der Anmeldedienst ist voruebergehend nicht verfuegbar.'])->onlyInput('identifier');
        } catch (\Throwable) {
            Audit::log('login.dash_protocol_error');

            return back()->withErrors(['identifier' => 'Anmeldung derzeit nicht moeglich.'])->onlyInput('identifier');
        }

        if ($r['result'] === 'mfa_required') {
            $request->session()->flash('mfa_required', true);

            return back()->onlyInput('identifier');
        }
        if ($r['result'] !== 'ok') {
            foreach ($keys as $k) {
                RateLimiter::hit($k, 300);
            }
            Audit::log('login.failed', null, null, ['result' => $r['result']]);

            // Einheitliche Meldung: kein Hinweis, ob das Konto existiert oder gesperrt ist.
            return back()->withErrors(['identifier' => 'Anmeldung fehlgeschlagen.'])->onlyInput('identifier');
        }

        try {
            $identity = $this->dash->identity($r['sub'], true);
        } catch (\Throwable) {
            return back()->withErrors(['identifier' => 'Anmeldung derzeit nicht moeglich.'])->onlyInput('identifier');
        }
        if (! $identity->isActive()) {
            Audit::log('login.denied_inactive', null, $identity->sub);

            return back()->withErrors(['identifier' => 'Anmeldung fehlgeschlagen.'])->onlyInput('identifier');
        }

        foreach ($keys as $k) {
            RateLimiter::clear($k);
        }
        $pending = $request->session()->get('pending_authorize');
        $started = $request->session()->get('login_started_at');
        // Session-Fixation: Laravel-Session-ID und CSRF-Token nach erfolgreichem Login erneuern.
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        $sso = $this->sessions->create($identity->sub, $identity->tenantId, $r['amr'] ?? ['pwd']);
        $request->session()->put('sso_sid', $sso->id);
        if ($started !== null) {
            $request->session()->put('login_started_at', $started);
        }
        Audit::log('login.success', null, $identity->sub, ['amr' => $r['amr'] ?? ['pwd']]);

        if (is_string($pending) && $pending !== '') {
            return redirect('/authorize?'.$pending);
        }

        return redirect()->route('account');
    }

    public function account(Request $request): View|RedirectResponse
    {
        $s = $this->sessions->valid($request->session()->get('sso_sid'));
        if ($s === null) {
            return redirect()->route('login');
        }

        return view('account');
    }
}
