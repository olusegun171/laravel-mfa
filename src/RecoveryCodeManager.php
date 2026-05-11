<?php

declare(strict_types=1);

namespace Olusegun171\TwoFactor;

/**
 * RecoveryCodeManager
 *
 * Generates, hashes, verifies, and invalidates one-time recovery codes.
 */
final class RecoveryCodeManager
{
    private int    $count;
    private string $algo;

    public function __construct(
        int    $count = 8,
        string $algo  = PASSWORD_BCRYPT
    ) {
        $this->count = $count;
        $this->algo  = $algo;
    }

    /**
     * Generate a fresh set of plain-text recovery codes.
     * Show these to the user exactly once — store only hashed versions.
     *
     * @return string[] e.g. ['A3F0-9E12-B84C', ...]
     */
    public function generate(): array
    {
        $codes = [];
        for ($i = 0; $i < $this->count; $i++) {
            $raw     = bin2hex(random_bytes(6));          // 12 hex chars
            $codes[] = strtoupper(implode('-', str_split($raw, 4))); // XXXX-XXXX-XXXX
        }
        return $codes;
    }

    /**
     * Hash all recovery codes for safe DB storage.
     *
     * @param  string[] $codes Plain-text codes
     * @return string[] Bcrypt hashes
     */
    public function hash(array $codes): array
    {
        return array_map(
            function (string $code) {
                return password_hash($code, $this->algo);
            },
            $codes
        );
    }

    /**
     * Verify an input code against a list of stored hashes.
     *
     * @param  string   $input       User-supplied code
     * @param  string[] $hashedCodes Stored hashed codes
     * @return int Index of the matched code, or -1 if no match
     */
    public function verify(string $input, array $hashedCodes): int
    {
        $input = strtoupper(trim($input));

        foreach ($hashedCodes as $index => $hash) {
            if (password_verify($input, $hash)) {
                return (int) $index;
            }
        }

        return -1;
    }

    /**
     * Remove a used recovery code by index and re-index the array.
     *
     * @param  string[] $hashedCodes
     * @param  int      $index
     * @return string[]
     */
    public function invalidate(array $hashedCodes, int $index): array
    {
        unset($hashedCodes[$index]);
        return array_values($hashedCodes);
    }
}
