<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array                                                  generate(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static array                                                  setup(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static void                                                   confirm(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user, string $code)
 * @method static void                                                   verify(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user, string $code)
 * @method static void                                                   verifyRecoveryCode(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user, string $code)
 * @method static array                                                  regenerateRecoveryCodes(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static int                                                    remainingRecoveryCodes(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static void                                                   disable(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static bool                                                   requiresChallenge(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static void                                                   storePendingUser(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
 * @method static \Illuminate\Contracts\Auth\Authenticatable|null       getPendingUser()
 * @method static bool                                                   hasPendingUser()
 * @method static void                                                   completePendingLogin()
 * @method static bool                                                   isPending(\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable $user)
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
