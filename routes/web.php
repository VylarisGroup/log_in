<?php

use App\Http\Controllers\Oidc\LoginController;
use App\Http\Controllers\Oidc\OidcController;
use App\Http\Controllers\Setup\SetupController;
use Illuminate\Support\Facades\Route;

Route::get('/', fn () => redirect()->route('login'));

// --- OpenID Connect Provider ---------------------------------------------------------------------------------
Route::get('/.well-known/openid-configuration', [OidcController::class, 'discovery'])->name('oidc.discovery');
Route::get('/.well-known/jwks.json', [OidcController::class, 'jwks'])->name('oidc.jwks');
Route::get('/authorize', [OidcController::class, 'authorizeEndpoint'])->middleware('throttle:60,1')->name('oidc.authorize');
Route::post('/token', [OidcController::class, 'token'])->middleware('throttle:120,1')->name('oidc.token');
Route::match(['get', 'post'], '/userinfo', [OidcController::class, 'userinfo'])->middleware('throttle:240,1')->name('oidc.userinfo');
Route::post('/revoke', [OidcController::class, 'revoke'])->middleware('throttle:60,1')->name('oidc.revoke');
Route::match(['get', 'post'], '/logout', [OidcController::class, 'logout'])->name('logout');

// --- Browser-Anmeldung ---------------------------------------------------------------------------------------
Route::get('/login', [LoginController::class, 'show'])->name('login');
Route::post('/login', [LoginController::class, 'store'])->middleware('throttle:30,1')->name('login.store');
Route::get('/account', [LoginController::class, 'account'])->name('account');

// --- Erstsetup und eng begrenzter Wartungszugang -------------------------------------------------------------
Route::prefix('setup')->middleware('throttle:60,1')->group(function () {
    Route::get('/', [SetupController::class, 'index'])->name('setup.index');
    Route::post('/token', [SetupController::class, 'token'])->name('setup.token');
    Route::get('/login', [SetupController::class, 'loginForm'])->name('setup.login');
    Route::post('/login', [SetupController::class, 'login'])->name('setup.login.store');
    Route::get('/recover/{token}', [SetupController::class, 'recover'])->name('setup.recover');
    Route::post('/install', [SetupController::class, 'install'])->name('setup.install');
    Route::get('/bundle', [SetupController::class, 'bundle'])->name('setup.bundle');
    Route::post('/admin', [SetupController::class, 'admin'])->name('setup.admin');
    Route::post('/keys', [SetupController::class, 'keys'])->name('setup.keys');
    Route::post('/dash/discover', [SetupController::class, 'discover'])->name('setup.dash.discover');
    Route::post('/dash/trust', [SetupController::class, 'trust'])->name('setup.dash.trust');
    Route::post('/client', [SetupController::class, 'client'])->name('setup.client');
    Route::post('/test', [SetupController::class, 'test'])->name('setup.test');
    Route::post('/finish', [SetupController::class, 'finish'])->name('setup.finish');
});
