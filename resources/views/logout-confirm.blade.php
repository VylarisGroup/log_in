@extends('layout')
@section('title', 'Abmelden - Vylaris')
@section('content')
<h1>Abmelden?</h1>
<form method="post" action="{{ route('logout') }}">@csrf<button type="submit">Jetzt abmelden</button></form>
@endsection
