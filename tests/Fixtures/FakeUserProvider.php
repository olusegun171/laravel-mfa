<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class FakeUserProvider implements UserProvider
{
    public function __construct(private readonly FakeUser $user) {}

    public function retrieveById($identifier): ?Authenticatable
    {
        return $this->user->getAuthIdentifier() === $identifier ? $this->user : null;
    }

    public function retrieveByToken($identifier, $token): ?Authenticatable { return null; }
    public function updateRememberToken(Authenticatable $user, $token): void {}
    public function retrieveByCredentials(array $credentials): ?Authenticatable { return null; }
    public function validateCredentials(Authenticatable $user, array $credentials): bool { return false; }
    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void {}
}
