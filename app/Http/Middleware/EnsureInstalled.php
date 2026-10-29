<?php

namespace App\Http\Middleware;

use App\Support\ApiError;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpFoundation\Response;

/** Solange die Datenbank nicht eingerichtet ist, fuehrt jede Seite zum Setup-Assistenten (kein Fehler 500). */
class EnsureInstalled
{
    private static ?bool $installed = null;

    public static function installed(): bool
    {
        if (self::$installed === null) {
            try {
                self::$installed = Schema::hasTable('settings');
            } catch (\Throwable) {
                self::$installed = false;
            }
        }

        return self::$installed;
    }

    public static function reset(): void
    {
        self::$installed = null;
    }

    public function handle(Request $request, Closure $next): Response
    {
        if (self::installed() || $request->is('setup', 'setup/*', 'up')) {
            return $next($request);
        }
        if ($request->is('api/*')) {
            return ApiError::response('service_unavailable');
        }
        if ($request->is('.well-known/*', 'token', 'userinfo', 'revoke', 'authorize')) {
            return response()->json(['error' => 'temporarily_unavailable'], 503);
        }

        return redirect('/setup');
    }
}
