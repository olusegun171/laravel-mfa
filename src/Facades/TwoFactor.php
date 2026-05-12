<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array                                                  generate(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
 * @method static array                                                  setup(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
 * @method static void                                                   confirm(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user, string $code)
 * @method static void                                                   verify(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user, string $code)
 * @method static void                                                   verifyRecoveryCode(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user, string $code)
 * @method static array                                                  regenerateRecoveryCodes(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
 * @method static int                                                    remainingRecoveryCodes(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
 * @method static void                                                   disable(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
 * @method static bool                                                   requiresChallenge(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
 * @method static void                                                   storePendingUser(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null       getPendingUser()
 * @method static bool                                                   hasPendingUser()
 * @method static void                                                   completePendingLogin()
 * @method static bool                                                   isPending(\Olusegun171\TwoFactor\Contracts\TwoFactorAuthenticatable $user)
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
