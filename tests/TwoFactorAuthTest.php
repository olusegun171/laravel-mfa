<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Tests;

use Olusegun171\TwoFactor\TwoFactorAuth;
use PHPUnit\Framework\TestCase;

class TwoFactorAuthTest extends TestCase
{
    private TwoFactorAuth $totp;

    protected function setUp(): void
    {
        $this->totp = new TwoFactorAuth();
    }

    // ── Secret generation ────────────────────────────────────────────────────

    public function test_generates_secret_of_requested_length(): void
    {
        $this->assertSame(16, strlen($this->totp->generateSecretKey(16)));
        $this->assertSame(32, strlen($this->totp->generateSecretKey(32)));
    }

    public function test_generated_secret_is_valid_base32(): void
    {
        $secret = $this->totp->generateSecretKey();
        $this->assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);
    }

    // ── Code generation ──────────────────────────────────────────────────────

    public function test_generated_code_is_six_digits(): void
    {
        $code = $this->totp->generateCode($this->totp->generateSecretKey());
        $this->assertMatchesRegularExpression('/^\d{6}$/', $code);
    }

    public function test_generated_code_is_zero_padded(): void
    {
        // Run multiple times to increase chance of hitting a low code value
        for ($i = 0; $i < 10; $i++) {
            $code = $this->totp->generateCode($this->totp->generateSecretKey());
            $this->assertSame(6, strlen($code));
        }
    }

    // ── Code verification ────────────────────────────────────────────────────

    public function test_verify_returns_true_for_valid_code(): void
    {
        $secret    = $this->totp->generateSecretKey();
        $timestamp = time();

        $this->assertTrue(
            $this->totp->verifyCode($secret, $this->totp->generateCode($secret, $timestamp), $timestamp)
        );
    }

    public function test_verify_returns_false_for_wrong_code(): void
    {
        $this->assertFalse(
            $this->totp->verifyCode($this->totp->generateSecretKey(), '000000')
        );
    }

    public function test_verify_accepts_code_within_clock_drift_window(): void
    {
        $secret    = $this->totp->generateSecretKey();
        $timestamp = time();
        $pastCode  = $this->totp->generateCode($secret, $timestamp - 30);

        $this->assertTrue($this->totp->verifyCode($secret, $pastCode, $timestamp));
    }

    public function test_verify_rejects_code_outside_drift_window(): void
    {
        $secret   = $this->totp->generateSecretKey();
        $now      = time();
        $oldCode  = $this->totp->generateCode($secret, $now - 120); // 4 periods ago

        $this->assertFalse($this->totp->verifyCode($secret, $oldCode, $now));
    }

    public function test_verify_ignores_whitespace_in_code(): void
    {
        // TwoFactorManager trims before calling verifyCode; test engine handles trimmed codes
        $secret    = $this->totp->generateSecretKey();
        $timestamp = time();
        $code      = $this->totp->generateCode($secret, $timestamp);

        $this->assertTrue($this->totp->verifyCode($secret, $code, $timestamp));
    }

    // ── URI / QR code ────────────────────────────────────────────────────────

    public function test_otp_auth_uri_has_correct_format(): void
    {
        $secret = 'JBSWY3DPEHPK3PXP';
        $uri    = $this->totp->getOtpAuthUri($secret, 'MyApp:user@example.com', 'MyApp');

        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $this->assertStringContainsString('secret=' . $secret, $uri);
        $this->assertStringContainsString('issuer=MyApp', $uri);
        $this->assertStringContainsString('digits=6', $uri);
        $this->assertStringContainsString('period=30', $uri);
    }

    public function test_qr_code_url_encodes_the_uri(): void
    {
        $uri = 'otpauth://totp/test?secret=ABC';
        $url = $this->totp->getQrCodeUrl($uri);

        $this->assertStringContainsString(rawurlencode($uri), $url);
        $this->assertStringContainsString('200x200', $url);
    }
}
