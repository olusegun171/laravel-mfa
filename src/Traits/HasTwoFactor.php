<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Traits;

/**
 * @property string|null                            $two_factor_secret
 * @property string|null                            $two_factor_recovery_codes
 * @property \Illuminate\Support\Carbon|string|null $two_factor_confirmed_at
 */
trait HasTwoFactor
{
    public function initializeHasTwoFactor(): void
    {
        $this->mergeCasts([
            'two_factor_confirmed_at' => 'datetime',
        ]);
    }

    /**
     * The identifier shown in the QR code label (e.g. email).
     * Override in your model if needed.
     */
    public function getTwoFactorIdentifier(): string
    {
        return $this->email ?? (string) $this->getAuthIdentifier();
    }

    public function hasTwoFactorEnabled(): bool
    {
        return $this->two_factor_confirmed_at !== null;
    }

    /**
     * Setup has been initiated but the user has not yet confirmed their first code.
     */
    public function hasTwoFactorPending(): bool
    {
        return $this->two_factor_secret !== null && $this->two_factor_confirmed_at === null;
    }
}
