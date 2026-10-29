@extends('layout')
@section('title', 'Setup - Vylaris log_in')
@section('content')
<h1>Setup</h1>
@if($completed)
<p class="muted">Die Einrichtung ist abgeschlossen. Wartungszugang: <a href="{{ route('setup.login') }}">Setup-Administrator</a>. Wiederherstellung nur per Server-Befehl <code>php artisan login:recovery:issue</code>.</p>
@else
<p class="muted">Gib das Setup-Token ein. Du findest es nur auf dem Server in der Datei <code>{{ $tokenPath }}</code>.</p>
<form method="post" action="{{ route('setup.token') }}">@csrf
<label for="token">Setup-Token</label><input id="token" name="token" required autocomplete="off">
@if(session('error'))<p class="err">{{ session('error') }}</p>@endif
@error('token')<p class="err">{{ $message }}</p>@enderror
<button>Weiter</button></form>
@endif
@endsection
