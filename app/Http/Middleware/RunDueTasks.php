<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

/**
 * "Pseudo-Cron" fuer Webhosting ohne Cron-Eintrag: nach der Antwort werden faellige Aufgaben (Wartung, Backup)
 * hoechstens einmal pro Minute ausgefuehrt. Bei echtem Cron PSEUDO_CRON=false setzen.
 */
class RunDueTasks
{
    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        if (! config('vylaris.pseudo_cron') || ! EnsureInstalled::installed()) {
            return;
        }
        try {
            if (Cache::add('vylaris:pseudo-cron', 1, 60)) {
                Artisan::call('schedule:run');
            }
        } catch (\Throwable $e) {
            report($e);
        }
    }
}
