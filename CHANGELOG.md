# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-11

### Added

- **TOTP engine** — RFC 6238 compliant, 6-digit, 30-second time-step (`TwoFactorAuth`)
- **AES-256-CBC encryption** — TOTP secrets encrypted at rest using a 32-byte slice of `APP_KEY` (`SecretEncryptor`)
- **Recovery codes** — 8 bcrypt-hashed one-time backup codes with invalidation on use (`RecoveryCodeManager`)
- **`TwoFactorManager`** — high-level orchestrator for the full 2FA lifecycle:
  - `setup()` — generates secret, QR code URI, and recovery codes; persists encrypted values to the user
  - `confirm()` — verifies the user's first TOTP code and activates 2FA
  - `verify()` — verifies a TOTP code during the login challenge
  - `verifyRecoveryCode()` — verifies and permanently invalidates a recovery code
  - `regenerateRecoveryCodes()` — replaces all recovery codes with a fresh set
  - `remainingRecoveryCodes()` — returns the count of unused recovery codes
  - `disable()` — clears all 2FA columns on the user
  - `isEnabled()` / `isPending()` — status helpers
- **`HasTwoFactor` trait** — Eloquent-aware trait for user models; adds `hasTwoFactorEnabled()`, `hasTwoFactorPending()`, and Eloquent casts for `two_factor_confirmed_at`
- **`TwoFactor` facade** — full IDE autocompletion via `@method` docblocks
- **`TwoFactorServiceProvider`** — auto-discovered; registers `TwoFactorManager` as a singleton bound to `APP_KEY` and `APP_NAME`
- **Artisan install command** — `php artisan two-factor:install --guard=web` resolves the table from the guard's Eloquent model and generates a migration
- **Publishable config** — `php artisan vendor:publish --tag=two-factor-config` exposes TOTP digits, period, window, and algorithm
- **GitHub Actions CI** — test matrix across PHP 8.1/8.2/8.3 and Laravel 10/11/12
- **±1 time-step clock-drift tolerance** — configurable via `two-factor.totp.window`
