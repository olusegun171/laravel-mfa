<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor;

use Olusegun171\TwoFactor\Exceptions\EncryptionException;

/**
 * SecretEncryptor
 *
 * AES-256-CBC encryption for storing TOTP secrets safely in your database.
 * The encryption key should be a 32-byte value from your application config.
 */
final class SecretEncryptor
{
    private const CIPHER = 'AES-256-CBC';
    private const IV_LEN = 16;

    private string $key;

    /**
     * @param string $key 32-byte encryption key (use env variable in production)
     */
    public function __construct(string $key)
    {
        if (strlen($key) !== 32) {
            throw new EncryptionException('Encryption key must be exactly 32 bytes.');
        }
        $this->key = $key;
    }

    /**
     * Encrypt a TOTP secret for DB storage.
     *
     * @throws EncryptionException
     */
    public function encrypt(string $plaintext): string
    {
        $iv        = random_bytes(self::IV_LEN);
        $encrypted = openssl_encrypt($plaintext, self::CIPHER, $this->key, 0, $iv);

        if ($encrypted === false) {
            throw new EncryptionException('Failed to encrypt secret: ' . openssl_error_string());
        }

        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt a stored TOTP secret.
     *
     * @throws EncryptionException
     */
    public function decrypt(string $ciphertext): string
    {
        $data = base64_decode($ciphertext, true);

        if ($data === false || strlen($data) <= self::IV_LEN) {
            throw new EncryptionException('Invalid ciphertext.');
        }

        $iv        = substr($data, 0, self::IV_LEN);
        $encrypted = substr($data, self::IV_LEN);
        $decrypted = openssl_decrypt($encrypted, self::CIPHER, $this->key, 0, $iv);

        if ($decrypted === false) {
            throw new EncryptionException('Failed to decrypt secret: ' . openssl_error_string());
        }

        return $decrypted;
    }
}
