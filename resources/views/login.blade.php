@extends('layout')
@section('title', 'Anmelden - Vylaris')
@section('content')
<h1>Anmelden</h1>
<form method="post" action="{{ route('login.store') }}" autocomplete="on">
@csrf
<label for="identifier">E-Mail oder Benutzername</label>
<input id="identifier" name="identifier" value="{{ old('identifier') }}" required autofocus autocomplete="username">
<label for="password">Passwort</label>
<input id="password" name="password" type="password" required autocomplete="current-password">
@if($mfa)
<label for="mfa_code">Bestaetigungscode (MFA)</label>
<input id="mfa_code" name="mfa_code" inputmode="numeric" autocomplete="one-time-code" required>
<p class="muted">Bitte Passwort und Code erneut eingeben.</p>
@endif
@error('identifier')<p class="err">{{ $message }}</p>@enderror
<button type="submit">Anmelden</button>
</form>
@endsection
