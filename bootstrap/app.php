<?php

use App\Http\Middleware\EnsureInstalled;
use App\Http\Middleware\RunDueTasks;
use App\Http\Middleware\SecurityHeaders;
use App\Support\ApiError;
use App\Support\EnvFile;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

// Web-Erstaufruf (z. B. Webhosting nach dem Entpacken): fehlende .env / fehlenden APP_KEY automatisch anlegen.
if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
    $https = (($_SERVER['HTTPS'] ?? '') !== '' && $_SERVER['HTTPS'] !== 'off') || strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
    EnvFile::provision(dirname(__DIR__), (string) ($_SERVER['HTTP_HOST'] ?? 'localhost'), $https);
}

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function () {
            Route::middleware([])->group(base_path('routes/api.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(EnsureInstalled::class);
        $middleware->append(SecurityHeaders::class);
        $middleware->append(RunDueTasks::class);
        // Maschinenendpunkte authentifizieren sich selbst (Client-Credentials, Bearer-Token); kein Browser-CSRF.
        $middleware->validateCsrfTokens(except: ['token', 'userinfo', 'revoke']);
        if ($proxies = env('TRUSTED_PROXIES')) {
            $middleware->trustProxies(at: $proxies === '*' ? '*' : explode(',', $proxies));
        }
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
        // Einheitlicher Fehlervertrag fuer /api/vylaris/*: keine Stacktraces, keine internen Details.
        $exceptions->render(function (Throwable $e, Request $request) {
            if (! $request->is('api/vylaris/*')) {
                return null;
            }

            return match (true) {
                $e instanceof ThrottleRequestsException => ApiError::response('rate_limited'),
                $e instanceof ValidationException => ApiError::response('validation_failed', null, $e->errors()),
                $e instanceof NotFoundHttpException,
                $e instanceof MethodNotAllowedHttpException => ApiError::response('resource_not_found'),
                $e instanceof ModelNotFoundException => ApiError::response('resource_not_found'),
                $e instanceof HttpExceptionInterface && $e->getStatusCode() === 413 => ApiError::response('validation_failed', 'Request body too large'),
                default => ApiError::response('internal_error'),
            };
        });
    })->create();
