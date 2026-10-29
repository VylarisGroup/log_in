@extends('layout')
@section('title', 'Setup-Wartung - Vylaris')
@section('content')
<h1>Setup-Administrator</h1>
<form method="post" action="{{ route('setup.login.store') }}">@csrf
<label>Benutzername</label><input name="username" required autocomplete="username">
<label>Passwort</label><input name="password" type="password" required autocomplete="current-password">
<label>TOTP-Code</label><input name="totp_code" inputmode="numeric" required autocomplete="one-time-code">
@error('login')<p class="err">{{ $message }}</p>@enderror
<button>Anmelden</button></form>
@endsection
