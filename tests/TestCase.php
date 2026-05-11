<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Tests;

use Olusegun171\TwoFactor\TwoFactorServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [TwoFactorServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('a', 32)));
        $app['config']->set('app.name', 'TestApp');
    }
}
