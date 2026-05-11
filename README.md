# laravel-mfa

Multi-factor authentication for Laravel. Works with Google Authenticator, Authy, 1Password, Bitwarden, and any other RFC 6238 compatible app.

[![Tests](https://github.com/olusegun171/laravel-mfa/actions/workflows/tests.yml/badge.svg)](https://github.com/olusegun171/laravel-mfa/actions/workflows/tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/olusegun171/laravel-mfa.svg)](https://packagist.org/packages/olusegun171/laravel-mfa)
[![Total Downloads](https://img.shields.io/packagist/dt/olusegun171/laravel-mfa.svg)](https://packagist.org/packages/olusegun171/laravel-mfa)
[![PHP](https://img.shields.io/badge/PHP-%3E%3D8.1-blue)](https://php.net)
[![Laravel](https://img.shields.io/badge/Laravel-10%2F11%2F12-red)](https://laravel.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Features

- TOTP codes — RFC 6238 compliant, 6-digit, 30-second window
- QR code URI generation for any authenticator app
- AES-256-CBC encrypted secret storage
- 8 bcrypt-hashed one-time recovery codes
- Clock-drift tolerance (±1 time-step)
- `TwoFactor` facade + `HasTwoFactor` Eloquent trait

---

## Requirements

- PHP 8.1+
- Laravel 10, 11, or 12

---

## Installation

```bash
composer require olusegun171/laravel-mfa
```

The service provider and `TwoFactor` facade are registered automatically via package auto-discovery.

---

## Setup

### 1. Publish the config

```bash
php artisan vendor:publish --tag=two-factor-config
```

### 2. Generate the migration

```bash
# Resolves the table from the guard's Eloquent model automatically
php artisan two-factor:install --guard=web

# Or pass the table directly
php artisan two-factor:install --table=admins

php artisan migrate
```

Adds three nullable columns to your table:

```
two_factor_secret           — AES-256-CBC encrypted TOTP secret
two_factor_recovery_codes   — JSON array of bcrypt-hashed one-time backup codes
two_factor_confirmed_at     — timestamp set when the user confirms their first code
```

### 3. Add the trait to your model

```php
use Olusegun171\TwoFactor\Traits\HasTwoFactor;

class User extends Authenticatable
{
    use HasTwoFactor;
}
```

---

## Usage

### Enable 2FA (setup flow)

```php
use Olusegun171\TwoFactor\Facades\TwoFactor;

$setup = TwoFactor::setup($user);

// $setup contains:
// [
//   'secret'         => 'BASE32SECRET',
//   'qr_code_url'    => 'https://api.qrserver.com/...',
//   'otp_auth_uri'   => 'otpauth://totp/...',
//   'recovery_codes' => ['XXXX-XXXX-XXXX', ...],  // show once, never again
// ]

// Display $setup['qr_code_url'] as an <img src="...">
// Show recovery codes to the user — they won't be shown again
```

The encrypted secret and hashed recovery codes are saved to the database immediately. `two_factor_confirmed_at` is `null` until the user confirms.

### Confirm setup

```php
use Olusegun171\TwoFactor\Exceptions\InvalidCodeException;

try {
    TwoFactor::confirm($user, $request->code);
    // two_factor_confirmed_at is now set — 2FA is active
} catch (InvalidCodeException $e) {
    return back()->withErrors(['code' => $e->getMessage()]);
}
```

### Login challenge

After verifying the user's password, check if 2FA is required:

```php
if (TwoFactor::isEnabled($user)) {
    // Show the 2FA challenge form, then on submission:
    try {
        TwoFactor::verify($user, $request->code);
        // Code is valid — complete the login
    } catch (InvalidCodeException $e) {
        return back()->withErrors(['code' => $e->getMessage()]);
    }
}
```

### Recovery code fallback

```php
try {
    TwoFactor::verifyRecoveryCode($user, $request->recovery_code);
    // Code accepted and permanently invalidated — complete the login
} catch (InvalidCodeException $e) {
    return back()->withErrors(['code' => $e->getMessage()]);
}
```

### Disable 2FA

```php
TwoFactor::disable($user);
// Clears two_factor_secret, two_factor_recovery_codes, two_factor_confirmed_at
```

### Regenerate recovery codes

```php
$codes = TwoFactor::regenerateRecoveryCodes($user); // string[]
// Old codes are invalidated immediately — show the new ones to the user once
```

---

## Status Helpers

```php
TwoFactor::isEnabled($user);  // true once two_factor_confirmed_at is set
TwoFactor::isPending($user);  // true if setup was started but not yet confirmed

TwoFactor::remainingRecoveryCodes($user); // int — unused codes remaining

// On the model (via HasTwoFactor trait)
$user->hasTwoFactorEnabled();
$user->hasTwoFactorPending();
```

---

## Configuration

```php
// config/two-factor.php
return [
    'issuer' => env('MFA_ISSUER', null), // shown in authenticator apps; defaults to app name

    'totp' => [
        'digits'    => 6,
        'period'    => 30,   // seconds per time-step
        'window'    => 1,    // ±1 period tolerance for clock drift
        'algorithm' => 'sha1',
    ],
];
```

---

## Security Notes

- **Rate-limit** the challenge endpoint — 5 attempts per minute is a reasonable starting point.
- **Serve over HTTPS** — codes in transit must be encrypted.
- **Recovery codes are shown once** — only bcrypt hashes are stored.
- All comparisons use `hash_equals()` for constant-time evaluation.
- TOTP secrets are encrypted with AES-256-CBC using a 32-byte slice of your `APP_KEY`.
- **Never log** `two_factor_secret` or `two_factor_recovery_codes`.

---

## License

MIT — see [LICENSE](LICENSE)
