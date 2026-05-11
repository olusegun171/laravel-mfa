<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor;

/**
 * TwoFactorAuth
 *
 * Google Authenticator compatible TOTP engine.
 * Implements RFC 6238 (TOTP) and RFC 4226 (HOTP).
 * Zero external dependencies.
 */
final class TwoFactorAuth
{
    private const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    private int    $digits;
    private int    $period;
    private int    $window;
    private string $algorithm;

    public function __construct(
        int    $digits    = 6,
        int    $period    = 30,
        int    $window    = 1,
        string $algorithm = 'sha1'
    ) {
        $this->digits    = $digits;
        $this->period    = $period;
        $this->window    = $window;
        $this->algorithm = $algorithm;
    }

    // -------------------------------------------------------------------------
    // Secret Key Management
    // -------------------------------------------------------------------------

    /**
     * Generate a cryptographically secure Base32 secret key.
     *
     * @param int $length Number of Base32 characters (multiples of 8 recommended)
     */
    public function generateSecretKey(int $length = 16): string
    {
        $secret = '';
        $bytes  = random_bytes($length);
        for ($i = 0; $i < $length; $i++) {
            $secret .= self::BASE32_CHARS[ord($bytes[$i]) & 31];
        }
        return $secret;
    }

    // -------------------------------------------------------------------------
    // TOTP Code Generation & Verification
    // -------------------------------------------------------------------------

    /**
     * Generate a TOTP code for the given secret and timestamp.
     *
     * @param string   $secret    Base32-encoded secret
     * @param int|null $timestamp Unix timestamp (defaults to now)
     */
    public function generateCode(string $secret, ?int $timestamp = null): string
    {
        if ($timestamp === null) {
            $timestamp = time();
        }
        $timeStep    = (int) floor($timestamp / $this->period);
        $secretBin   = $this->base32Decode($secret);
        $timeBytes   = pack('N*', 0, $timeStep);

        $hmac   = hash_hmac($this->algorithm, $timeBytes, $secretBin, true);
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0F;
        $code   = (
            ((ord($hmac[$offset])     & 0x7F) << 24) |
            ((ord($hmac[$offset + 1]) & 0xFF) << 16) |
            ((ord($hmac[$offset + 2]) & 0xFF) <<  8) |
             (ord($hmac[$offset + 3]) & 0xFF)
        ) % (10 ** $this->digits);

        return str_pad((string) $code, $this->digits, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a user-supplied TOTP code. Checks ±window steps to handle clock drift.
     *
     * @param string   $secret    Base32-encoded secret
     * @param string   $code      User-supplied code
     * @param int|null $timestamp Unix timestamp (defaults to now)
     */
    public function verifyCode(string $secret, string $code, ?int $timestamp = null): bool
    {
        if ($timestamp === null) {
            $timestamp = time();
        }

        for ($i = -$this->window; $i <= $this->window; $i++) {
            $expected = $this->generateCode($secret, $timestamp + ($i * $this->period));
            if (hash_equals($expected, $code)) {
                return true;
            }
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // OTP Auth URI & QR Code
    // -------------------------------------------------------------------------

    /**
     * Build an otpauth:// URI for Google Authenticator / compatible apps.
     *
     * @param string $secret Base32-encoded secret
     * @param string $label  Usually "AppName:user@email.com"
     * @param string $issuer Displayed in the authenticator app
     */
    public function getOtpAuthUri(string $secret, string $label, string $issuer): string
    {
        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d',
            rawurlencode($label),
            $secret,
            rawurlencode($issuer),
            strtoupper($this->algorithm),
            $this->digits,
            $this->period
        );
    }

    /**
     * Return a QR code image URL (via api.qrserver.com — no library required).
     *
     * For self-hosted QR codes, see: https://github.com/endroid/qr-code
     *
     * @param string $otpAuthUri The full otpauth:// URI
     * @param int    $size       Image size in pixels
     */
    public function getQrCodeUrl(string $otpAuthUri, int $size = 200): string
    {
        return sprintf(
            'https://api.qrserver.com/v1/create-qr-code/?size=%dx%d&data=%s',
            $size,
            $size,
            rawurlencode($otpAuthUri)
        );
    }

    // -------------------------------------------------------------------------
    // Base32 Helpers (internal)
    // -------------------------------------------------------------------------

    private function base32Decode(string $input): string
    {
        $input    = strtoupper(rtrim($input, '='));
        $output   = '';
        $buffer   = 0;
        $bitsLeft = 0;

        for ($i = 0, $len = strlen($input); $i < $len; $i++) {
            $value = strpos(self::BASE32_CHARS, $input[$i]);
            if ($value === false) {
                continue;
            }
            $buffer    = ($buffer << 5) | $value;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output   .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }

        return $output;
    }
}
