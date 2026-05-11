<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Tests;

use Olusegun171\TwoFactor\Exceptions\InvalidCodeException;
use Olusegun171\TwoFactor\RecoveryCodeManager;
use Olusegun171\TwoFactor\SecretEncryptor;
use Olusegun171\TwoFactor\Tests\Fixtures\FakeUser;
use Olusegun171\TwoFactor\TwoFactorAuth;
use Olusegun171\TwoFactor\TwoFactorManager;

class TwoFactorManagerTest extends TestCase
{
    private TwoFactorManager $manager;
    private TwoFactorAuth    $totp;
    private FakeUser         $user;

    protected function setUp(): void
    {
        parent::setUp(); // boots the Laravel app so now() works

        $this->totp    = new TwoFactorAuth();
        $this->manager = new TwoFactorManager(
            $this->totp,
            new SecretEncryptor(str_repeat('a', 32)),
            new RecoveryCodeManager(),
            'TestApp',
        );
        $this->user = new FakeUser();
    }

    // ── setup() ──────────────────────────────────────────────────────────────

    public function test_setup_returns_expected_keys(): void
    {
        $result = $this->manager->setup($this->user);

        $this->assertArrayHasKey('secret', $result);
        $this->assertArrayHasKey('qr_code_url', $result);
        $this->assertArrayHasKey('otp_auth_uri', $result);
        $this->assertArrayHasKey('recovery_codes', $result);
    }

    public function test_setup_persists_encrypted_secret_to_user(): void
    {
        $this->manager->setup($this->user);

        $this->assertNotNull($this->user->two_factor_secret);
        $this->assertNotNull($this->user->two_factor_recovery_codes);
        $this->assertNull($this->user->two_factor_confirmed_at);
    }

    public function test_setup_returns_eight_recovery_codes(): void
    {
        $result = $this->manager->setup($this->user);

        $this->assertCount(8, $result['recovery_codes']);
    }

    public function test_setup_marks_2fa_as_pending(): void
    {
        $this->manager->setup($this->user);

        $this->assertTrue($this->manager->isPending($this->user));
        $this->assertFalse($this->manager->isEnabled($this->user));
    }

    public function test_setup_otp_auth_uri_contains_issuer_and_email(): void
    {
        $result = $this->manager->setup($this->user);

        $this->assertStringContainsString('TestApp', $result['otp_auth_uri']);
        $this->assertStringContainsString('user%40example.com', $result['otp_auth_uri']);
    }

    // ── confirm() ────────────────────────────────────────────────────────────

    public function test_confirm_activates_2fa_with_valid_code(): void
    {
        $setup = $this->manager->setup($this->user);
        $code  = $this->totp->generateCode($setup['secret']);

        $this->manager->confirm($this->user, $code);

        $this->assertTrue($this->manager->isEnabled($this->user));
        $this->assertFalse($this->manager->isPending($this->user));
        $this->assertNotNull($this->user->two_factor_confirmed_at);
    }

    public function test_confirm_throws_on_wrong_code(): void
    {
        $this->manager->setup($this->user);

        $this->expectException(InvalidCodeException::class);
        $this->manager->confirm($this->user, '000000');
    }

    public function test_confirm_throws_when_setup_not_initiated(): void
    {
        $this->expectException(InvalidCodeException::class);
        $this->manager->confirm($this->user, '123456');
    }

    // ── verify() ─────────────────────────────────────────────────────────────

    public function test_verify_succeeds_with_valid_code(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));

        $this->manager->verify($this->user, $this->totp->generateCode($setup['secret']));
        $this->assertTrue(true); // no exception thrown
    }

    public function test_verify_throws_on_wrong_code(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));

        $this->expectException(InvalidCodeException::class);
        $this->manager->verify($this->user, '000000');
    }

    public function test_verify_throws_when_2fa_not_enabled(): void
    {
        $this->expectException(InvalidCodeException::class);
        $this->manager->verify($this->user, '123456');
    }

    // ── verifyRecoveryCode() ─────────────────────────────────────────────────

    public function test_verify_recovery_code_succeeds_with_valid_code(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));

        $this->manager->verifyRecoveryCode($this->user, $setup['recovery_codes'][0]);
        $this->assertTrue(true); // no exception
    }

    public function test_verify_recovery_code_invalidates_used_code(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));

        $this->manager->verifyRecoveryCode($this->user, $setup['recovery_codes'][0]);

        $this->assertSame(7, $this->manager->remainingRecoveryCodes($this->user));
    }

    public function test_verify_recovery_code_cannot_be_reused(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));
        $this->manager->verifyRecoveryCode($this->user, $setup['recovery_codes'][0]);

        $this->expectException(InvalidCodeException::class);
        $this->manager->verifyRecoveryCode($this->user, $setup['recovery_codes'][0]);
    }

    public function test_verify_recovery_code_throws_on_invalid_code(): void
    {
        $this->manager->setup($this->user);

        $this->expectException(InvalidCodeException::class);
        $this->manager->verifyRecoveryCode($this->user, 'XXXX-XXXX-XXXX');
    }

    // ── regenerateRecoveryCodes() ─────────────────────────────────────────────

    public function test_regenerate_returns_eight_new_codes(): void
    {
        $this->manager->setup($this->user);
        $newCodes = $this->manager->regenerateRecoveryCodes($this->user);

        $this->assertCount(8, $newCodes);
    }

    public function test_regenerate_invalidates_old_codes(): void
    {
        $setup    = $this->manager->setup($this->user);
        $oldCode  = $setup['recovery_codes'][0];

        $this->manager->regenerateRecoveryCodes($this->user);

        $this->expectException(InvalidCodeException::class);
        $this->manager->verifyRecoveryCode($this->user, $oldCode);
    }

    // ── remainingRecoveryCodes() ──────────────────────────────────────────────

    public function test_remaining_recovery_codes_is_eight_after_setup(): void
    {
        $this->manager->setup($this->user);

        $this->assertSame(8, $this->manager->remainingRecoveryCodes($this->user));
    }

    public function test_remaining_recovery_codes_decrements_after_use(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));
        $this->manager->verifyRecoveryCode($this->user, $setup['recovery_codes'][0]);

        $this->assertSame(7, $this->manager->remainingRecoveryCodes($this->user));
    }

    // ── disable() ────────────────────────────────────────────────────────────

    public function test_disable_clears_all_2fa_columns(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));

        $this->manager->disable($this->user);

        $this->assertNull($this->user->two_factor_secret);
        $this->assertNull($this->user->two_factor_recovery_codes);
        $this->assertNull($this->user->two_factor_confirmed_at);
    }

    public function test_disable_marks_2fa_as_not_enabled(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));
        $this->manager->disable($this->user);

        $this->assertFalse($this->manager->isEnabled($this->user));
        $this->assertFalse($this->manager->isPending($this->user));
    }

    // ── isEnabled() / isPending() ─────────────────────────────────────────────

    public function test_is_not_enabled_or_pending_for_fresh_user(): void
    {
        $this->assertFalse($this->manager->isEnabled($this->user));
        $this->assertFalse($this->manager->isPending($this->user));
    }

    public function test_is_pending_after_setup_before_confirm(): void
    {
        $this->manager->setup($this->user);

        $this->assertTrue($this->manager->isPending($this->user));
        $this->assertFalse($this->manager->isEnabled($this->user));
    }

    public function test_is_enabled_and_not_pending_after_confirm(): void
    {
        $setup = $this->manager->setup($this->user);
        $this->manager->confirm($this->user, $this->totp->generateCode($setup['secret']));

        $this->assertTrue($this->manager->isEnabled($this->user));
        $this->assertFalse($this->manager->isPending($this->user));
    }
}
