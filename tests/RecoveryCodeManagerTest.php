<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor\Tests;

use Olusegun171\TwoFactor\RecoveryCodeManager;
use PHPUnit\Framework\TestCase;

class RecoveryCodeManagerTest extends TestCase
{
    private RecoveryCodeManager $manager;

    protected function setUp(): void
    {
        $this->manager = new RecoveryCodeManager(8);
    }

    // ── Generation ───────────────────────────────────────────────────────────

    public function test_generates_correct_count(): void
    {
        $this->assertCount(8, $this->manager->generate());
    }

    public function test_codes_match_expected_format(): void
    {
        foreach ($this->manager->generate() as $code) {
            $this->assertMatchesRegularExpression('/^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/', $code);
        }
    }

    public function test_codes_are_unique(): void
    {
        $codes = $this->manager->generate();
        $this->assertSame(count($codes), count(array_unique($codes)));
    }

    // ── Hashing ──────────────────────────────────────────────────────────────

    public function test_hash_returns_same_count_as_input(): void
    {
        $plain = $this->manager->generate();
        $this->assertCount(count($plain), $this->manager->hash($plain));
    }

    public function test_hashes_are_different_from_plain_codes(): void
    {
        $plain  = $this->manager->generate();
        $hashed = $this->manager->hash($plain);

        foreach ($plain as $i => $code) {
            $this->assertNotSame($code, $hashed[$i]);
        }
    }

    // ── Verification ─────────────────────────────────────────────────────────

    public function test_verify_returns_correct_index_for_valid_code(): void
    {
        $plain  = $this->manager->generate();
        $hashed = $this->manager->hash($plain);

        $this->assertSame(0, $this->manager->verify($plain[0], $hashed));
        $this->assertSame(3, $this->manager->verify($plain[3], $hashed));
    }

    public function test_verify_is_case_insensitive(): void
    {
        $plain  = $this->manager->generate();
        $hashed = $this->manager->hash($plain);

        $this->assertSame(0, $this->manager->verify(strtolower($plain[0]), $hashed));
    }

    public function test_verify_returns_minus_one_for_wrong_code(): void
    {
        $hashed = $this->manager->hash($this->manager->generate());
        $this->assertSame(-1, $this->manager->verify('XXXX-XXXX-XXXX', $hashed));
    }

    public function test_verify_returns_minus_one_for_empty_list(): void
    {
        $this->assertSame(-1, $this->manager->verify('XXXX-XXXX-XXXX', []));
    }

    // ── Invalidation ─────────────────────────────────────────────────────────

    public function test_invalidate_removes_code_at_index(): void
    {
        $plain    = $this->manager->generate();
        $hashed   = $this->manager->hash($plain);
        $first    = $hashed[0];
        $remaining = $this->manager->invalidate($hashed, 0);

        $this->assertCount(7, $remaining);
        $this->assertNotContains($first, $remaining);
    }

    public function test_invalidate_re_indexes_the_array(): void
    {
        $hashed    = $this->manager->hash($this->manager->generate());
        $remaining = $this->manager->invalidate($hashed, 0);

        $this->assertSame(array_values($remaining), $remaining);
    }

    public function test_invalidated_code_no_longer_verifies(): void
    {
        $plain     = $this->manager->generate();
        $hashed    = $this->manager->hash($plain);
        $remaining = $this->manager->invalidate($hashed, 0);

        $this->assertSame(-1, $this->manager->verify($plain[0], $remaining));
    }
}
