<?php

use App\Http\Controllers\Api\DiscoveryController;
use App\Http\Controllers\Api\ManagementApiController as Api;
use App\Http\Middleware\EnforceIdempotency;
use App\Http\Middleware\VerifyMachineRequest;
use Illuminate\Support\Facades\Route;

/*
 | Vylaris Unified API v1 (log_in-Seite). Einziger Pfadraum fuer Maschinenkommunikation: /api/vylaris/v1.
 | Jeder authentifizierte Aufruf: Authorization: Bearer <Service-Token> + Ed25519-Signatur (VerifyMachineRequest).
 | Weder Reseller noch Tools duerfen diese Endpunkte aufrufen. Discovery ist oeffentlich und unsigniert (dokumentierte Ausnahme).
 */
Route::get('/.well-known/vylaris-login', [DiscoveryController::class, 'show'])->name('vylaris.discovery.well_known');
Route::get(config('vylaris.api_prefix').'/discovery', [DiscoveryController::class, 'show'])->middleware('throttle:60,1')->name('vylaris.discovery');

$machine = fn (string $scope) => ['throttle:300,1', VerifyMachineRequest::class.':'.$scope, EnforceIdempotency::class];

Route::prefix(config('vylaris.api_prefix'))->group(function () use ($machine) {
    Route::middleware($machine('service.health'))->get('/health', [Api::class, 'health']);

    Route::middleware($machine('pairings.manage'))->group(function () {
        Route::get('/pairing-window', [Api::class, 'windowShow']);
        Route::post('/pairing-window', [Api::class, 'windowOpen']);
        Route::delete('/pairing-window', [Api::class, 'windowClose']);
        Route::post('/pairings', [Api::class, 'pairingCreate']);
        Route::get('/pairings/{id}', [Api::class, 'pairingShow']);
        Route::post('/pairings/{id}/{action}', [Api::class, 'pairingAction'])->where('action', 'approve|reject|cancel|confirm|credentials-ack');
    });

    Route::middleware($machine('clients.read'))->group(function () {
        Route::get('/clients', [Api::class, 'clientIndex']);
        Route::get('/clients/{id}', [Api::class, 'clientShow']);
    });
    Route::middleware($machine('clients.manage'))->group(function () {
        Route::patch('/clients/{id}', [Api::class, 'clientUpdate']);
        Route::post('/clients/{id}/{action}', [Api::class, 'clientAction'])->where('action', 'suspend|resume|disconnect|report-error|rotate-secret');
    });

    Route::middleware($machine('keys.manage'))->group(function () {
        Route::get('/keys', [Api::class, 'keyIndex']);
        Route::post('/keys/rotate', [Api::class, 'keyRotate']);
        Route::post('/keys/{key_id}/revoke', [Api::class, 'keyRevoke']);
    });

    Route::middleware($machine('users.revoke'))->group(function () {
        Route::post('/users/{sub}/revoke', [Api::class, 'userRevoke']);
        Route::post('/users/{sub}/refresh', [Api::class, 'userRefresh']);
    });

    Route::middleware($machine('service.rotate'))->post('/service-tokens/rotate', [Api::class, 'serviceTokenRotate']);
});
