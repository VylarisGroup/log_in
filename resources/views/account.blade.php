@extends('layout')
@section('title', 'Angemeldet - Vylaris')
@section('content')
<h1>Du bist angemeldet</h1>
<p class="muted">Oeffne ein Vylaris-Tool, um fortzufahren.</p>
<form method="post" action="{{ route('logout') }}">@csrf<button type="submit">Abmelden</button></form>
@endsection
