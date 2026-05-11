<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Tests;

use Olusegun171\TwoFactor\Exceptions\EncryptionException;
use Olusegun171\TwoFactor\SecretEncryptor;
use PHPUnit\Framework\TestCase;

class SecretEncryptorTest extends TestCase
{
    private SecretEncryptor $enc;

    protected function setUp(): void
    {
        $this->enc = new SecretEncryptor(str_repeat('k', 32));
    }

    public function test_encrypt_then_decrypt_returns_original(): void
    {
        $original = 'JBSWY3DPEHPK3PXP';

        $this->assertSame($original, $this->enc->decrypt($this->enc->encrypt($original)));
    }

    public function test_encrypt_produces_different_ciphertexts_each_time(): void
    {
        // Random IV means same plaintext gives different ciphertext on each call
        $c1 = $this->enc->encrypt('SECRET');
        $c2 = $this->enc->encrypt('SECRET');

        $this->assertNotSame($c1, $c2);
    }

    public function test_ciphertext_is_base64_encoded(): void
    {
        $ciphertext = $this->enc->encrypt('SECRET');

        $this->assertNotFalse(base64_decode($ciphertext, true));
    }

    public function test_throws_on_key_shorter_than_32_bytes(): void
    {
        $this->expectException(EncryptionException::class);
        new SecretEncryptor('short');
    }

    public function test_throws_on_key_longer_than_32_bytes(): void
    {
        $this->expectException(EncryptionException::class);
        new SecretEncryptor(str_repeat('x', 33));
    }

    public function test_throws_on_invalid_ciphertext(): void
    {
        $this->expectException(EncryptionException::class);
        $this->enc->decrypt('not-valid-ciphertext');
    }

    public function test_throws_on_empty_ciphertext(): void
    {
        $this->expectException(EncryptionException::class);
        $this->enc->decrypt('');
    }

    public function test_different_keys_cannot_decrypt_each_other(): void
    {
        $enc2       = new SecretEncryptor(str_repeat('z', 32));
        $ciphertext = $this->enc->encrypt('SECRET');

        $this->expectException(EncryptionException::class);
        $enc2->decrypt($ciphertext);
    }
}
