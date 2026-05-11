<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array setup(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static void  confirm(\Illuminate\Contracts\Auth\Authenticatable $user, string $code)
 * @method static void  verify(\Illuminate\Contracts\Auth\Authenticatable $user, string $code)
 * @method static void  verifyRecoveryCode(\Illuminate\Contracts\Auth\Authenticatable $user, string $code)
 * @method static array regenerateRecoveryCodes(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static int   remainingRecoveryCodes(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static void  disable(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static bool  isEnabled(\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static bool  isPending(\Illuminate\Contracts\Auth\Authenticatable $user)
 *
 * @see \Olusegun171\TwoFactor\TwoFactorManager
 */
class TwoFactor extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'two-factor';
    }
}
