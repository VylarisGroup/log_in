@extends('layout')
@section('title', 'Setup-Assistent - Vylaris')
@section('content')
<style>main{max-width:680px}h2{font-size:1rem;margin:24px 0 4px}.ok{color:#087443}.bad{color:var(--err)}pre{white-space:pre-wrap;word-break:break-all;background:rgba(127,127,127,.12);padding:10px;border-radius:8px;font-size:.8rem}details{margin:10px 0}</style>
<h1>log_in einrichten</h1>
@if(session('status'))<p class="ok">{{ session('status') }}</p>@endif
@if(session('error'))<p class="err">{{ session('error') }}</p>@endif
@if($completed)<p class="muted">Modus: <strong>{{ $mode }}</strong>. Wartungsfunktionen: Dash-Vertrauen, Client und Verbindungstest.</p>@endif

@unless($completed)
<h2>Schritt 1: Installation</h2>
@if($adminDone && $keysDone)
<div class="ok">OK - Datenbank, Schluessel und Setup-Administrator sind eingerichtet (der Administrator laeuft nach 72 h oder mit der Dash-Aktivierung ab).</div>
@else
@foreach($env as $name => $c)<div class="{{ $c['ok'] ? 'ok' : 'bad' }}">{{ $c['ok'] ? 'OK' : 'FEHLT' }} - {{ $name }} <span class="muted">{{ $c['info'] }}</span></div>@endforeach
<form method="post" action="{{ route('setup.install') }}">@csrf
<label>Oeffentliche Adresse (Issuer, nicht mehr aenderbar)</label><input name="issuer" value="{{ old('issuer', $issuer) }}" required>
@unless($installed)
<label>Datenbank</label>
<select name="db_mode" onchange="document.getElementById('mysql').style.display=this.value==='mysql'?'block':'none'">
<option value="sqlite" @selected(old('db_mode','sqlite')==='sqlite')>SQLite (keine Zugangsdaten noetig, empfohlen fuer Webhosting ohne Last)</option>
<option value="mysql" @selected(old('db_mode')==='mysql')>MySQL / MariaDB</option></select>
<div id="mysql" style="display:{{ old('db_mode')==='mysql' ? 'block' : 'none' }}">
<label>Host</label><input name="db_host" value="{{ old('db_host','localhost') }}">
<label>Port</label><input name="db_port" value="{{ old('db_port','3306') }}">
<label>Datenbankname</label><input name="db_name" value="{{ old('db_name') }}">
<label>Benutzer</label><input name="db_user" value="{{ old('db_user') }}">
<label>Passwort</label><input name="db_password" type="password" autocomplete="off"></div>
@endunless
@if(! $adminDone)
<h2>Setup-Administrator (zeitlich begrenzt)</h2>
<p class="muted">TOTP-Geheimnis in einer Authenticator-App einrichten: <code>{{ $totpSecret }}</code></p>
<pre>{{ $totpUri }}</pre>
<label>Benutzername</label><input name="username" value="{{ old('username') }}" required>
<label>Passwort (min. 14 Zeichen)</label><input name="password" type="password" required autocomplete="new-password">
<label>Passwort wiederholen</label><input name="password_confirmation" type="password" required autocomplete="new-password">
<label>TOTP-Code</label><input name="totp_code" inputmode="numeric" required>
@endif
@error('install')<p class="err">{{ $message }}</p>@enderror
<button>Jetzt installieren</button></form>
@endif
@endunless

@if($completed || $keysDone)
<h2>Schritt 2: Dash verbinden</h2>
@if($dashDone)<div class="ok">OK - Dash vertraut: {{ $dashBase }}</div>@endif
@if($clientDone)<div class="ok">OK - Dash als OIDC-Anwendung registriert.</div>@endif
@if($registerError)<p class="err">{{ $registerError }}</p>@endif
<form method="post" action="{{ route('setup.dash.discover') }}">@csrf
<label>Dash-Adresse (z. B. dash.example.ch)</label><input name="dash_url" value="{{ old('dash_url', $dashBase ? preg_replace('#^https?://#', '', $dashBase) : '') }}" required>
<button>Dash suchen</button></form>
@error('dash')<p class="err">{{ $message }}</p>@enderror
@if($discovered)
<p>Gefunden: <strong>{{ $discovered['name'] }}</strong> ({{ $discovered['installation_id'] }})</p>
<p class="muted">Gleiche diesen Fingerprint mit der Anzeige in Dash ab und tippe ihn zur Bestaetigung ein. Danach wird Dash automatisch registriert.</p>
<pre>{{ $discovered['fingerprint'] }}</pre>
<form method="post" action="{{ route('setup.dash.trust') }}">@csrf<label>Fingerprint</label><input name="fingerprint" required autocomplete="off"><button>Bestaetigen und registrieren</button></form>
@endif
@if($bundleReady)
<p><a href="{{ route('setup.bundle') }}"><strong>dash-bootstrap.json herunterladen</strong></a> und in Dash importieren. Die Datei enthaelt Geheimnisse; nach dem Import loeschen.</p>
@endif
@if($dashDone)
<details><summary>Redirect-URIs anpassen / neu registrieren (neues Geheimnis)</summary>
<form method="post" action="{{ route('setup.client') }}">@csrf
<label>Redirect-URIs von Dash (eine pro Zeile)</label><textarea name="redirect_uris" rows="2" style="width:100%">{{ old('redirect_uris', $dashBase ? $dashBase.'/auth/callback' : '') }}</textarea>
<label>Post-Logout-URIs (optional)</label><textarea name="post_logout_uris" rows="2" style="width:100%">{{ old('post_logout_uris', $dashBase ? $dashBase.'/' : '') }}</textarea>
@error('client')<p class="err">{{ $message }}</p>@enderror
<button>Neu registrieren</button></form></details>
@endif
@endif

@if($clientDone)
<h2>Schritt 3: Testen und abschliessen</h2>
@if($testOk)<div class="ok">OK - signierter Health-Aufruf erfolgreich</div>@else<p class="muted">Voraussetzung: Dash hat das Bundle importiert. Der Verbindungstest laeuft beim Abschluss automatisch.</p>@endif
<form method="post" action="{{ route('setup.test') }}">@csrf<button>Verbindung testen</button></form>
@unless($completed)
@if($checks)@foreach($checks as $n => $c)<div class="{{ $c['ok'] ? 'ok' : 'bad' }}">{{ $c['ok'] ? 'OK' : 'FEHLER' }} - {{ $n }}</div>@endforeach @endif
<form method="post" action="{{ route('setup.finish') }}">@csrf<button>Pruefen und Setup abschliessen</button></form>
@endunless
@endif
@endsection
