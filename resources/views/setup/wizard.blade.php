@extends('layout')
@section('title', 'Setup-Assistent - Vylaris')
@section('content')
<style>main{max-width:640px}h2{font-size:1rem;margin:22px 0 4px}.ok{color:#087443}.bad{color:var(--err)}pre{white-space:pre-wrap;word-break:break-all;background:rgba(127,127,127,.12);padding:10px;border-radius:8px;font-size:.8rem}</style>
<h1>log_in einrichten</h1>
@if(session('status'))<p class="ok">{{ session('status') }}</p>@endif
@if(session('error'))<p class="err">{{ session('error') }}</p>@endif
@if($completed)<p class="muted">Modus: <strong>{{ $mode }}</strong>. Wartungsfunktionen: Dash-Vertrauen, Client und Verbindungstest.</p>@endif

@unless($completed)
<h2>1. Umgebung</h2>
@foreach($env as $name => $c)<div class="{{ $c['ok'] ? 'ok' : 'bad' }}">{{ $c['ok'] ? 'OK' : 'FEHLT' }} - {{ $name }} <span class="muted">{{ $c['info'] }}</span></div>@endforeach

<h2>2. Setup-Administrator (zeitlich begrenzt)</h2>
@if($adminDone)<div class="ok">OK - angelegt (laeuft nach 72 h oder mit der Dash-Aktivierung ab)</div>
@else
<p class="muted">TOTP-Geheimnis in einer Authenticator-App einrichten: <code>{{ $totpSecret }}</code></p>
<pre>{{ $totpUri }}</pre>
<form method="post" action="{{ route('setup.admin') }}">@csrf
<label>Benutzername</label><input name="username" required>
<label>Passwort (min. 14 Zeichen)</label><input name="password" type="password" required autocomplete="new-password">
<label>Passwort wiederholen</label><input name="password_confirmation" type="password" required autocomplete="new-password">
<label>TOTP-Code</label><input name="totp_code" inputmode="numeric" required>
@error('admin')<p class="err">{{ $message }}</p>@enderror
<button>Administrator anlegen</button></form>
@endif

<h2>3. Schluessel</h2>
@if($keysDone)<div class="ok">OK - Token-Signaturschluessel (RS256) und Ed25519-Schluessel fuer die Dash-API erzeugt</div>
@elseif($adminDone)<form method="post" action="{{ route('setup.keys') }}">@csrf<button>Schluessel erzeugen</button></form>@endif
@endunless

@if($completed || $keysDone)
<h2>4. Dash verbinden</h2>
@if($dashDone)<div class="ok">OK - Dash vertraut: {{ $dashBase }}</div>@endif
<form method="post" action="{{ route('setup.dash.discover') }}">@csrf
<label>Dash-URL (HTTPS)</label><input name="dash_url" value="{{ old('dash_url', $dashBase) }}" required>
<button>Dash entdecken</button></form>
@error('dash')<p class="err">{{ $message }}</p>@enderror
@if($discovered)
<p>Gefunden: <strong>{{ $discovered['name'] }}</strong> ({{ $discovered['installation_id'] }})</p>
<p class="muted">Gleiche diesen Fingerprint in Dash ab und tippe ihn zur Bestaetigung ein:</p>
<pre>{{ $discovered['fingerprint'] }}</pre>
<form method="post" action="{{ route('setup.dash.trust') }}">@csrf<label>Fingerprint</label><input name="fingerprint" required autocomplete="off"><button>Vertrauen bestaetigen</button></form>
@endif
@endif

@if($dashDone)
<h2>5. Dash als erste OIDC-Anwendung</h2>
@if($clientDone && ! $bundle)<div class="ok">OK - registriert. Bundle liegt (0600) unter storage/app/bootstrap/dash-bootstrap.json.</div>@endif
@if($bundle)
<p class="err">Einmalig sichtbar. Ohne Speicherung ist das Geheimnis verloren (dann neu registrieren):</p>
<pre>{{ json_encode($bundle, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES) }}</pre>
@endif
<form method="post" action="{{ route('setup.client') }}">@csrf
<label>Redirect-URIs von Dash (eine pro Zeile)</label><textarea name="redirect_uris" rows="2" style="width:100%">{{ old('redirect_uris') }}</textarea>
<label>Post-Logout-URIs (optional)</label><textarea name="post_logout_uris" rows="2" style="width:100%">{{ old('post_logout_uris') }}</textarea>
@error('client')<p class="err">{{ $message }}</p>@enderror
<button>{{ $clientDone ? 'Neu registrieren (neues Geheimnis)' : 'Registrieren' }}</button></form>
@endif

@if($clientDone)
<h2>6. Dash-API-Verbindung testen</h2>
@if($testOk)<div class="ok">OK - signierter Health-Aufruf erfolgreich</div>@endif
<p class="muted">Voraussetzung: Dash hat den oeffentlichen Schluessel aus dem Bundle importiert.</p>
<form method="post" action="{{ route('setup.test') }}">@csrf<button>Verbindung testen</button></form>
@endif

@if($testOk && ! $completed)
<h2>7. Abschluss und Integritaetstest</h2>
@if($checks)@foreach($checks as $n => $c)<div class="{{ $c['ok'] ? 'ok' : 'bad' }}">{{ $c['ok'] ? 'OK' : 'FEHLER' }} - {{ $n }}</div>@endforeach @endif
<form method="post" action="{{ route('setup.finish') }}">@csrf<button>Pruefen und Setup abschliessen</button></form>
@endif
@endsection
