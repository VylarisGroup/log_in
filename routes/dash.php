<?php

use App\Http\Controllers\Api\DashApiController;
use App\Http\Middleware\VerifyDashSignature;
use Illuminate\Support\Facades\Route;

/*
 | Server-zu-Server-API fuer Dash. Kein Session-/Cookie-Zugriff; jede Anfrage ist per Ed25519 signiert (VerifyDashSignature).
 | Weder Reseller noch Tools duerfen diese Endpunkte aufrufen.
 */
Route::prefix('api/dash/v1')->middleware(['throttle:300,1', VerifyDashSignature::class])->group(function () {
    Route::get('/health', [DashApiController::class, 'health']);

    Route::post('/pairings', [DashApiController::class, 'pairingCreate']);
    Route::get('/pairings/{id}', [DashApiController::class, 'pairingShow']);
    Route::post('/pairings/{id}/{action}', [DashApiController::class, 'pairingAction'])->where('action', 'dash-approve|dash-reject|cancel|tool-confirm|credentials-ack');

    Route::get('/clients', [DashApiController::class, 'clientIndex']);
    Route::get('/clients/{id}', [DashApiController::class, 'clientShow']);
    Route::patch('/clients/{id}', [DashApiController::class, 'clientUpdate']);
    Route::post('/clients/{id}/{action}', [DashApiController::class, 'clientAction'])->where('action', 'suspend|resume|disconnect|report-error|rotate-secret');

    Route::get('/keys', [DashApiController::class, 'keyIndex']);
    Route::post('/keys/rotate', [DashApiController::class, 'keyRotate']);
    Route::post('/keys/{kid}/revoke', [DashApiController::class, 'keyRevoke']);

    Route::post('/users/{sub}/revoke', [DashApiController::class, 'userRevoke']);
    Route::post('/users/{sub}/refresh', [DashApiController::class, 'userRefresh']);
});
