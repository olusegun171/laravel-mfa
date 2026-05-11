<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Exceptions;

/**
 * Thrown when a supplied TOTP code or recovery code fails verification.
 */
class InvalidCodeException extends TwoFactorAuthException
{
}
