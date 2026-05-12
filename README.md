# laravel-mfa

Multi-factor authentication for Laravel. Works with Google Authenticator, Authy, 1Password, Bitwarden, and any other RFC 6238 compatible app.

[![Tests](https://github.com/olusegun171/laravel-mfa/actions/workflows/tests.yml/badge.svg)](https://github.com/olusegun171/laravel-mfa/actions/workflows/tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/olusegun171/laravel-mfa.svg)](https://packagist.org/packages/olusegun171/laravel-mfa)
[![Total Downloads](https://img.shields.io/packagist/dt/olusegun171/laravel-mfa.svg)](https://packagist.org/packages/olusegun171/laravel-mfa)
[![PHP](https://img.shields.io/badge/PHP-%3E%3D8.1-blue)](https://php.net)
[![Laravel](https://img.shields.io/badge/Laravel-10%2F11%2F12%2F13-red)](https://laravel.com)
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
- Laravel 10, 11, 12, or 13

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

### 2. Run the migration

```bash
# Resolves the table from the guard's Eloquent model automatically
php artisan two-factor:install --guard=web

# Or pass the table directly
php artisan two-factor:install --table=admins

php artisan migrate
```

This adds three nullable columns to your users table:

| Column | Description |
|---|---|
| `two_factor_secret` | AES-256-CBC encrypted TOTP secret |
| `two_factor_recovery_codes` | JSON array of bcrypt-hashed one-time backup codes |
| `two_factor_confirmed_at` | Timestamp set when the user confirms their first code |

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

See the [Integration](#integration) section for full usage examples split by authenticated and unauthenticated context.

---

## Status Helpers

```php
TwoFactor::remainingRecoveryCodes($user); // number of unused backup codes

// Model methods via HasTwoFactor trait
$user->hasTwoFactorEnabled();  // true once two_factor_confirmed_at is set
$user->hasTwoFactorPending();  // true if setup started but not yet confirmed
```

---

## QR Code Identifier

By default the QR code label uses `getAuthIdentifier()` — typically the user's primary key. To show something friendlier (like an email address) in the authenticator app, add `getTwoFactorIdentifier()` to your model:

```php
class User extends Authenticatable
{
    use HasTwoFactor;

    public function getTwoFactorIdentifier(): string
    {
        return $this->email;
    }
}
```

The label will appear as `YourApp:user@example.com` inside the authenticator app.

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
- **Recovery codes are shown once** — only bcrypt hashes are stored in the database.
- All comparisons use `hash_equals()` for constant-time evaluation.
- TOTP secrets are encrypted with AES-256-CBC using a 32-byte slice of your `APP_KEY`.
- **Never log** `two_factor_secret` or `two_factor_recovery_codes`.

---

## Integration

---

### Authenticated context (settings or an enforced page)

The user is already logged in. They enable 2FA from their account settings or a dedicated page to enforce the 2fa, scan the QR code, and confirm with their first code.

**Enable and show the QR code**

```php
$data = TwoFactor::generate($user);

// Pass $data to your view:
// $data['qr_code_url']    — <img src="{{ $data['qr_code_url'] }}">
// $data['secret']         — manual entry fallback
// $data['recovery_codes'] — show once, store somewhere safe
```

**Confirm the first code**

```php
try {
    TwoFactor::confirm($user, $request->code);
} catch (InvalidCodeException $e) {
    return back()->withErrors(['code' => $e->getMessage()]);
}
```

**Disable 2FA**

```php
TwoFactor::disable($user);
```

**Regenerate recovery codes**

```php
$codes = TwoFactor::regenerateRecoveryCodes($user); // string[]
```

---

### Unauthenticated context (login flow)

The user is not yet logged in. `Auth::login()` is not called until the 2FA code is verified — the user is fully unauthenticated between the password step and the code step.

**Step 1 — Password check (`LoginController`)**

```php
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Olusegun171\TwoFactor\Facades\TwoFactor;

$user = User::where('email', $request->email)->first();

if (!$user || !Hash::check($request->password, $user->password)) {
    return back()->withErrors(['email' => 'Invalid credentials.']);
}

if (TwoFactor::requiresChallenge($user)) {
    return redirect()->route('two-factor.challenge');
}

// 2FA not set up — enforced: require setup before granting access
$setup = TwoFactor::setup($user);
return redirect()->route('two-factor.setup')->with('setup', $setup);
```

**Step 2 — Challenge routes**

Wrap the challenge routes with the `two-factor` middleware so they redirect to login if accessed directly (no pending session).

```php
Route::middleware('two-factor')->group(function () {
    Route::get('/two-factor/challenge',  [TwoFactorChallengeController::class, 'show'])->name('two-factor.challenge');
    Route::post('/two-factor/challenge', [TwoFactorChallengeController::class, 'store']);
    Route::post('/two-factor/recovery',  [TwoFactorChallengeController::class, 'recover']);
});
```

**Step 3 — Challenge controller**

```php
use Olusegun171\TwoFactor\Exceptions\InvalidCodeException;
use Olusegun171\TwoFactor\Facades\TwoFactor;

// Submit a TOTP code
public function store(Request $request)
{
    $user = TwoFactor::getPendingUser();

    try {
        TwoFactor::verify($user, $request->code);
    } catch (InvalidCodeException $e) {
        return back()->withErrors(['code' => $e->getMessage()]);
    }

    TwoFactor::completeChallenge();
    Auth::login($user);
    $request->session()->regenerate();

    return redirect()->intended('/dashboard');
}

// Submit a recovery code instead
public function recover(Request $request)
{
    $user = TwoFactor::getPendingUser();

    try {
        TwoFactor::verifyRecoveryCode($user, $request->recovery_code);
    } catch (InvalidCodeException $e) {
        return back()->withErrors(['recovery_code' => $e->getMessage()]);
    }

    TwoFactor::completeChallenge();
    Auth::login($user);
    $request->session()->regenerate();

    return redirect()->intended('/dashboard');
}
```

`completeChallenge()` clears the pending session state. The caller is responsible for `Auth::login()` and `session()->regenerate()`.

---

## License

MIT — see [LICENSE](LICENSE)
