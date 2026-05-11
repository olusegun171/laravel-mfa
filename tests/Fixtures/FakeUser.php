<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Minimal Eloquent-like user for testing.
 * Declares 2FA properties directly so they bypass Model::__get/__set,
 * and overrides save() to avoid any database connection.
 */
class FakeUser extends Model implements Authenticatable
{
    public ?string $two_factor_secret         = null;
    public ?string $two_factor_recovery_codes = null;
    public mixed   $two_factor_confirmed_at   = null;
    public string  $email                     = 'user@example.com';

    public function save(array $options = []): bool
    {
        return true;
    }

    public function getAuthIdentifierName(): string  { return 'id'; }
    public function getAuthIdentifier(): mixed       { return 1; }
    public function getAuthPasswordName(): string    { return 'password'; }
    public function getAuthPassword(): string        { return ''; }
    public function getRememberToken(): ?string      { return null; }
    public function setRememberToken($value): void   {}
    public function getRememberTokenName(): string   { return 'remember_token'; }
}
