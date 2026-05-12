<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Contract for models that support two-factor authentication.
 * Implement this alongside the HasTwoFactor trait.
 *
 * @property string|null $two_factor_secret
 * @property string|null $two_factor_recovery_codes
 * @property \Illuminate\Support\Carbon|null $two_factor_confirmed_at
 */
interface TwoFactorAuthenticatable extends Authenticatable
{
    public function getTwoFactorIdentifier(): string;

    public function save(array $options = []): bool;
}
