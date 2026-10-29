<?php

namespace App\Services\Vylaris;

/** Strikte Pruefung von Redirect- und Logout-URIs: exakte Werte, HTTPS, Host innerhalb der Tool-Domain, keine Wildcards. */
final class UriPolicy
{
    /**
     * @param  list<mixed>  $uris
     * @return list<string> Fehlermeldungen (leer = gueltig)
     */
    public static function validate(array $uris, string $domain, bool $required = true): array
    {
        $errors = [];
        if ($required && $uris === []) {
            return ['mindestens eine URI erforderlich'];
        }
        if (count($uris) > 10) {
            $errors[] = 'maximal 10 URIs';
        }
        foreach ($uris as $u) {
            $err = self::check($u, $domain);
            if ($err !== null) {
                $errors[] = $err;
            }
        }

        return $errors;
    }

    private static function check(mixed $u, string $domain): ?string
    {
        if (! is_string($u) || $u === '' || strlen($u) > 512 || preg_match('/[\x00-\x20*\\\\]/', $u)) {
            return 'ungueltige URI';
        }
        $p = parse_url($u);
        if ($p === false || ! isset($p['scheme'], $p['host']) || isset($p['user']) || isset($p['pass']) || isset($p['fragment']) || str_contains($u, '#')) {
            return 'URI muss absolut sein, ohne Zugangsdaten und ohne Fragment: '.$u;
        }
        $host = strtolower($p['host']);
        $loopback = in_array($host, ['localhost', '127.0.0.1', '[::1]'], true);
        if ($p['scheme'] === 'http') {
            if (! ($loopback && (config('app.env') !== 'production' || config('vylaris.dash.allow_http')))) {
                return 'nur HTTPS erlaubt: '.$u;
            }
        } elseif ($p['scheme'] !== 'https') {
            return 'Schema nicht erlaubt: '.$u;
        }
        $domain = strtolower($domain);
        if (! $loopback && $host !== $domain && ! str_ends_with($host, '.'.$domain)) {
            return 'Host liegt ausserhalb der registrierten Domain: '.$u;
        }

        return null;
    }

    public static function validDomain(string $d): bool
    {
        return (bool) preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $d) || $d === 'localhost';
    }
}
