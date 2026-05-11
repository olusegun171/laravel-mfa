<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Exceptions;

/**
 * Thrown when encryption or decryption of the TOTP secret fails.
 */
class EncryptionException extends TwoFactorAuthException
{
}
