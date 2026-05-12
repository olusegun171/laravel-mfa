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
     * Persists the encrypted secret and hashed recovery codes immediately.
     *
     * Returns:
     *   secret         — plain-text Base32 secret (for display only, not stored)
     *   qr_code_url    — URL to a QR code image the user scans
     *   otp_auth_uri   — raw otpauth:// URI
     *   recovery_codes — plain-text one-time backup codes (show once, never again)
     *
     * @return array<string, mixed>
     */
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

        $identifier = method_exists($user, 'getTwoFactorIdentifier')
            ? $user->getTwoFactorIdentifier()
            : (string) $user->getAuthIdentifier();

        $label      = $this->issuer . ':' . $identifier;
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

        session()->put('two_factor.login_id', $user->getAuthIdentifier());

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
        return count(json_decode($user->two_factor_recovery_codes ?? '[]', true));
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
     * Returns true if 2FA is enabled for the user, and stores them as a pending login.
     * The caller should redirect to the challenge route when this returns true.
     */
    public function requiresChallenge(Model&Authenticatable $user): bool
    {
        if (!$this->isEnabled($user)) {
            return false;
        }

        session()->put('two_factor.login_id', $user->getAuthIdentifier());

        return true;
    }

    /**
     * Store the pending user in the session after a successful password check.
     * Do NOT call Auth::login() until completePendingLogin() is called.
     */
    public function storePendingUser(Model&Authenticatable $user): void
    {
        session()->put('two_factor.login_id', $user->getAuthIdentifier());
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
    public function hasPendingUser(): bool
    {
        return session()->has('two_factor.login_id');
    }

    /**
     * Clear the pending login state after a successful 2FA challenge.
     * The caller is responsible for Auth::login() and session()->regenerate().
     */
    public function completePendingLogin(): void
    {
        session()->forget('two_factor.login_id');
    }

    // =========================================================================
    // Status helpers
    // =========================================================================

    /**
     * Return true if the user has completed 2FA setup (confirmed).
     */
    public function isEnabled(Model&Authenticatable $user): bool
    {
        return !empty($user->two_factor_confirmed_at);
    }

    /**
     * Return true if the user has started but not yet confirmed 2FA setup.
     */
    public function isPending(Model&Authenticatable $user): bool
    {
        return !empty($user->two_factor_secret) && empty($user->two_factor_confirmed_at);
    }
}
