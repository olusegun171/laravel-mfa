<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Exceptions;

/**
 * Thrown when 2FA operations are attempted on a user who has not enabled 2FA.
 */
class TwoFactorNotEnabledException extends TwoFactorAuthException
{
}
