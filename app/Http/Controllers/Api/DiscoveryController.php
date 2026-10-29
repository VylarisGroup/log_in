<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Setting;
use Illuminate\Http\JsonResponse;

/**
 * Oeffentliche, bewusst UNSIGNIERTE Vylaris-Discovery von log_in (Ausnahme von der Antwortsignatur).
 * Der Schluessel ist erst nach Fingerprint-Bestaetigung vertrauenswuerdig. OIDC-Metadaten: /.well-known/openid-configuration.
 */
class DiscoveryController extends Controller
{
    public function show(): JsonResponse
    {
        $issuer = config('vylaris.issuer');

        return response()->json(['data' => [
            'service' => 'log_in',
            'api_version' => config('vylaris.api_version'),
            'version' => config('vylaris.version'),
            'installation_id' => Setting::get('login.installation_id'),
            'name' => 'Vylaris log_in',
            'public_key' => Setting::get('login.sign_public'),
            'issuer' => $issuer,
            'api_base' => $issuer.config('vylaris.api_prefix'),
            'openid_configuration' => $issuer.'/.well-known/openid-configuration',
        ]])->header('Cache-Control', 'public, max-age=60');
    }
}
