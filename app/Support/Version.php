<?php

namespace App\Support;

/**
 * Versionsschema JJ.BB.CCDD (Tag: vJJ.BB.CCDD), z. B. v26.01.0200.
 *
 * JJ = Jahreskuerzel, BB = Hauptversion (grosse Neuerung, 01-99), CC = Nebenversion (kleine Updates, 00-99),
 * DD = Fehlerkorrekturen (00-20). Ueberlauf: DD > 20 -> CC erhoehen; CC > 99 -> BB erhoehen.
 */
final class Version
{
    public const PATTERN = '/^v?(\d{2})\.(\d{2})\.(\d{2})(\d{2})$/';

    /** @return array{year: int, major: int, minor: int, fix: int}|null null wenn kein gueltiges Schema */
    public static function parse(string $version): ?array
    {
        if (! preg_match(self::PATTERN, trim($version), $m) || (int) $m[2] < 1 || (int) $m[4] > 20) {
            return null;
        }

        return ['year' => (int) $m[1], 'major' => (int) $m[2], 'minor' => (int) $m[3], 'fix' => (int) $m[4]];
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
