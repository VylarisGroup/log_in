<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $h = $response->headers;
        $h->set('X-Content-Type-Options', 'nosniff');
        $h->set('X-Frame-Options', 'DENY');
        $h->set('Referrer-Policy', 'no-referrer');
        $h->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
        // Kein form-action: der Login endet in einer Weiterleitung zum Client (andere Origin).
        $h->set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'");
        if ($request->isSecure()) {
            $h->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }
        if (! $h->has('Cache-Control') || str_contains((string) $h->get('Cache-Control'), 'no-cache')) {
            $h->set('Cache-Control', 'no-store');
        }

        return $response;
    }
}
