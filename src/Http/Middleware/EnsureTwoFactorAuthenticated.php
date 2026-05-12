<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Olusegun171\TwoFactor\TwoFactorManager;
use Symfony\Component\HttpFoundation\Response;

class EnsureTwoFactorAuthenticated
{
    public function __construct(private readonly TwoFactorManager $manager) {}

    /**
     * Protect the 2FA challenge route.
     * Redirects to login if there is no pending login session — prevents direct
     * access to the challenge page without going through the password check first.
     */
    public function handle(Request $request, Closure $next, string $route = 'login'): Response
    {
        if (!$this->manager->hasPendingChallenge()) {
            return redirect()->route($route);
        }

        return $next($request);
    }
}
