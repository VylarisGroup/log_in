<?php

namespace App\Support;

/**
 * Versionsschema JJ.BB.CC[x] (Tag: vJJ.BB.CC[x]), z. B. v26.01.02 und die Fehlerkorrektur v26.01.02a.
 *
 * JJ = Jahreskuerzel, BB = Hauptversion (grosse Neuerung, 01-99), CC = Nebenversion (kleine Updates, 00-99),
 * x = Fehlerkorrektur als Buchstabe a-t (max. 20); ohne Buchstaben ist es das Release selbst.
 * Ueberlauf: nach t steigt CC; nach CC 99 steigt BB.
 */
final class Version
{
    public const PATTERN = '/^v?(\d{2})\.(\d{2})\.(\d{2})([a-t])?$/';

    /** @return array{year: int, major: int, minor: int, fix: int}|null fix 0 = Release, 1 = a ... 20 = t; null wenn kein gueltiges Schema */
    public static function parse(string $version): ?array
    {
        if (! preg_match(self::PATTERN, trim($version), $m) || (int) $m[2] < 1) {
            return null;
        }

        return ['year' => (int) $m[1], 'major' => (int) $m[2], 'minor' => (int) $m[3], 'fix' => isset($m[4]) ? ord($m[4]) - 96 : 0];
    }

    public static function isValid(string $version): bool
    {
        return self::parse($version) !== null;
    }

    /** Vergleich wie <=>; ungueltige Versionen gelten als aelter als jede gueltige. */
    public static function compare(string $a, string $b): int
    {
        $pa = self::parse($a);
        $pb = self::parse($b);
        if ($pa === null || $pb === null) {
            return ($pa !== null) <=> ($pb !== null);
        }

        return array_values($pa) <=> array_values($pb);
    }

    public static function current(): string
    {
        return (string) config('vylaris.version');
    }
}
