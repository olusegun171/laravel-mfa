<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor;

use Illuminate\Support\ServiceProvider;
use Olusegun171\TwoFactor\Commands\TwoFactorInstallCommand;
use Olusegun171\TwoFactor\RecoveryCodeManager;
use Olusegun171\TwoFactor\SecretEncryptor;
use Olusegun171\TwoFactor\TwoFactorAuth;
use Olusegun171\TwoFactor\TwoFactorManager;

class TwoFactorServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/two-factor.php', 'two-factor');

        $this->app->singleton(TwoFactorManager::class, function ($app) {
            $appKey = $app['config']['app.key'] ?? '';
            $rawKey = str_starts_with($appKey, 'base64:')
                ? base64_decode(substr($appKey, 7))
                : $appKey;

            $cfg = $app['config']['two-factor.totp'];

            $issuer = (string) $app['config']['two-factor.issuer'];

            return new TwoFactorManager(
                new TwoFactorAuth(
                    (int)    $cfg['digits'],
                    (int)    $cfg['period'],
                    (int)    $cfg['window'],
                    (string) $cfg['algorithm'],
                ),
                new SecretEncryptor(substr($rawKey, 0, 32)),
                new RecoveryCodeManager(),
                $issuer,
            );
        });

        $this->app->alias(TwoFactorManager::class, 'two-factor');
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/two-factor.php' => config_path('two-factor.php'),
            ], 'two-factor-config');

            $this->commands([TwoFactorInstallCommand::class]);
        }
    }
}
