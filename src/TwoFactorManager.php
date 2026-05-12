<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use Olusegun171\TwoFactor\Exceptions\InvalidCodeException;

class TwoFactorManager
{
    public function __construct(
        private readonly TwoFactorAuth       $totp,
        private readonly SecretEncryptor     $encryptor,
        private readonly RecoveryCodeManager $recovery,
        private readonly string              $issuer,
    ) {}

    // =========================================================================
    // Setup
    // =========================================================================

    /**
     * Generate a new TOTP secret, QR code, and recovery codes for the user.
     * Use this when the user is already authenticated (e.g. account settings page).
     *
     * @return array<string, mixed>
     */
    public function generate(Model&Authenticatable $user): array
    {
        $secret        = $this->totp->generateSecretKey();
        $recoveryCodes = $this->recovery->generate();

        $user->two_factor_secret         = $this->encryptor->encrypt($secret);
        $user->two_factor_recovery_codes = json_encode($this->recovery->hash($recoveryCodes));
        $user->two_factor_confirmed_at   = null;
        $user->save();

        $label      = "{$this->issuer}:{$user->getTwoFactorIdentifier()}";
        $otpAuthUri = $this->totp->getOtpAuthUri($secret, $label, $this->issuer);

        return [
            'secret'         => $secret,
            'qr_code_url'    => $this->totp->getQrCodeUrl($otpAuthUri),
            'otp_auth_uri'   => $otpAuthUri,
            'recovery_codes' => $recoveryCodes,
        ];
    }

    /**
     * Generate 2FA credentials and store the user as a pending login.
     * Use this during an enforced login flow where the user has not yet set up 2FA.
     *
     * @return array<string, mixed>
     */
    public function setup(Model&Authenticatable $user): array
    {
        $data = $this->generate($user);

        if (session()->isStarted()) {
            session()->put('two_factor.login_id', $user->getAuthIdentifier());
        }

        return $data;
    }

    /**
     * Verify the user's first TOTP code to confirm setup.
     * Sets two_factor_confirmed_at on success.
     *
     * @throws InvalidCodeException
     */
    public function confirm(Model&Authenticatable $user, string $code): void
    {
        if (empty($user->two_factor_secret)) {
            throw new InvalidCodeException('Two-factor setup has not been initiated.');
        }

        if (!$this->totp->verifyCode($this->encryptor->decrypt($user->two_factor_secret), trim($code))) {
            throw new InvalidCodeException('The provided two-factor authentication code is invalid.');
        }

        $user->two_factor_confirmed_at = now();
        $user->save();
    }

    // =========================================================================
    // Login challenge
    // =========================================================================

    /**
     * Verify a TOTP code during the login challenge.
     *
     * @throws InvalidCodeException
     */
    public function verify(Model&Authenticatable $user, string $code): void
    {
        if (empty($user->two_factor_secret) || empty($user->two_factor_confirmed_at)) {
            throw new InvalidCodeException('Two-factor authentication is not enabled.');
        }

        if (!$this->totp->verifyCode($this->encryptor->decrypt($user->two_factor_secret), trim($code))) {
            throw new InvalidCodeException('The provided two-factor authentication code is invalid.');
        }
    }

    /**
     * Verify a one-time recovery code and invalidate it on success.
     *
     * @throws InvalidCodeException
     */
    public function verifyRecoveryCode(Model&Authenticatable $user, string $code): void
    {
        $hashedCodes = json_decode($user->two_factor_recovery_codes ?? '[]', true);
        $matchIndex  = $this->recovery->verify($code, $hashedCodes);

        if ($matchIndex === -1) {
            throw new InvalidCodeException('The recovery code is invalid or has already been used.');
        }

        $user->two_factor_recovery_codes = json_encode(
            $this->recovery->invalidate($hashedCodes, $matchIndex)
        );
        $user->save();
    }

    // =========================================================================
    // Recovery codes
    // =========================================================================

    /**
     * Generate a fresh set of recovery codes and return the plain-text values.
     * The old codes are invalidated immediately.
     *
     * @return string[]
     */
    public function regenerateRecoveryCodes(Model&Authenticatable $user): array
    {
        $fresh                           = $this->recovery->generate();
        $user->two_factor_recovery_codes = json_encode($this->recovery->hash($fresh));
        $user->save();

        return $fresh;
    }

    /**
     * Return how many unused recovery codes the user has left.
     */
    public function remainingRecoveryCodes(Model&Authenticatable $user): int
    {
        return \count(json_decode($user->two_factor_recovery_codes ?? '[]', true));
    }

    // =========================================================================
    // Disable
    // =========================================================================

    /**
     * Disable 2FA and clear all 2FA columns on the user.
     */
    public function disable(Model&Authenticatable $user): void
    {
        $user->two_factor_secret         = null;
        $user->two_factor_recovery_codes = null;
        $user->two_factor_confirmed_at   = null;
        $user->save();
    }

    // =========================================================================
    // Session helpers for pending 2FA login state
    // =========================================================================

    /**
     * Returns true if 2FA is confirmed for the user.
     * In web context also stores the user as a pending login in the session.
     * The caller should redirect to the challenge route when this returns true.
     */
    public function requiresChallenge(Model&Authenticatable $user): bool
    {
        if (!$this->isEnabled($user)) {
            return false;
        }

        // Only store pending state when a session is available (web context).
        // Stateless API callers skip this — they carry identity in the request body instead.
        if (session()->isStarted()) {
            session()->put('two_factor.login_id', $user->getAuthIdentifier());
        }

        return true;
    }

    /**
     * Retrieve the pending user from the session, or null if none exists.
     */
    public function getPendingUser(): ?Authenticatable
    {
        $id = session()->get('two_factor.login_id');

        return $id !== null ? Auth::getProvider()->retrieveById($id) : null;
    }

    /**
     * Return true if there is a pending 2FA login in the session.
     */
    public function hasPendingChallenge(): bool
    {
        if (!session()->has('two_factor.login_id')) {
            return false;
        }

        $user = $this->getPendingUser();

        if ($user instanceof Model && (!empty($user->two_factor_secret) || $this->isEnabled($user))) {
            return true;
        }

        session()->forget('two_factor.login_id');
        return false;
    }

    /**
     * Clear the pending login state after a successful 2FA challenge.
     * The caller is responsible for Auth::login() and session()->regenerate().
     */
    public function completeChallenge(): void
    {
        session()->forget('two_factor.login_id');
    }

    // =========================================================================
    // Status helpers
    // =========================================================================

    /**
     * Internal check — use requiresChallenge() for all callers outside this class.
     */
    private function isEnabled(Model&Authenticatable $user): bool
    {
        return !empty($user->two_factor_confirmed_at);
    }
}
