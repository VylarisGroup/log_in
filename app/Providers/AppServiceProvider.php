<?php

namespace App\Providers;

use App\Services\Dash\DashClient;
use App\Services\Oidc\KeyManager;
use App\Services\Oidc\OidcContext;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->scoped(OidcContext::class);
        $this->app->singleton(KeyManager::class);
        $this->app->singleton(DashClient::class);
    }

    public function boot(): void
    {
        //
    }
}
