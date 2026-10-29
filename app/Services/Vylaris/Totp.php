<?php

namespace App\Services\Vylaris;

/** RFC-6238-TOTP (SHA-1, 6 Stellen, 30 s) fuer den lokalen Setup-Administrator. Endnutzer-MFA liegt bei Dash. */
final class Totp
{
    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function newSecret(): string
    {
        $raw = random_bytes(20);
        $out = '';
        $bits = '';
        foreach (str_split($raw) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[bindec(str_pad($chunk, 5, '0'))];
        }

        return $out;
    }

    public static function code(string $secret, int $counter): string
    {
        $key = self::decode($secret);
        $h = hash_hmac('sha1', pack('N2', 0, $counter), $key, true);
        $o = ord($h[19]) & 0xF;
        $n = ((ord($h[$o]) & 0x7F) << 24) | (ord($h[$o + 1]) << 16) | (ord($h[$o + 2]) << 8) | ord($h[$o + 3]);

        return str_pad((string) ($n % 1000000), 6, '0', STR_PAD_LEFT);
    }

    public static function verify(string $secret, string $code, ?int $now = null): bool
    {
        $code = preg_replace('/\s+/', '', $code);
        if (! preg_match('/^\d{6}$/', (string) $code)) {
            return false;
        }
        $counter = intdiv($now ?? time(), 30);
        $ok = false;
        foreach ([-1, 0, 1] as $d) {
            $ok = hash_equals(self::code($secret, $counter + $d), $code) || $ok;
        }

        return $ok;
    }

    public static function uri(string $secret, string $account, string $issuer = 'Vylaris log_in'): string
    {
        return 'otpauth://totp/'.rawurlencode($issuer.':'.$account).'?secret='.$secret.'&issuer='.rawurlencode($issuer);
    }

    private static function decode(string $b32): string
    {
        $bits = '';
        foreach (str_split(strtoupper($b32)) as $c) {
            $bits .= str_pad(decbin(strpos(self::ALPHABET, $c)), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }

        return $out;
    }
}
