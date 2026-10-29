<?php

namespace App\Services\Vylaris;

use Illuminate\Support\Facades\Log;

/**
 * SSRF-Schutz fuer alle ausgehenden Aufrufe an eine konfigurierte Gegenstelle (Dash):
 * nur HTTPS, keine Zugangsdaten in der URL, keine Loopback-/privaten/Link-Local-/reservierten Ziele,
 * Aufloesung wird geprueft und fuer die Verbindung festgenagelt (DNS-Rebinding), Redirects sind deaktiviert.
 *
 * Lockerungen (HTTP, private Ziele, DNS-Pruefung aus) gelten NUR ausserhalb der Produktion.
 */
final class SsrfGuard
{
    public static function relaxed(): bool
    {
        $wants = ! config('vylaris.ssrf.enforce') || config('vylaris.ssrf.allow_private') || config('vylaris.dash.allow_http');
        if ($wants && app()->isProduction()) {
            Log::critical('SSRF-Lockerung ist konfiguriert, wird in Produktion aber ignoriert.');

            return false;
        }

        return $wants;
    }

    /**
     * @return array{host: string, port: int, ip: ?string, scheme: string} geprueftes Ziel (ip = festzunagelnde Adresse)
     *
     * @throws \InvalidArgumentException
     */
    public static function check(string $url): array
    {
        $p = parse_url($url);
        $scheme = strtolower($p['scheme'] ?? '');
        $host = strtolower(trim((string) ($p['host'] ?? ''), '[]'));
        if ($host === '' || isset($p['user']) || isset($p['pass']) || isset($p['fragment'])) {
            throw new \InvalidArgumentException('Ungueltige URL');
        }
        $relaxed = self::relaxed();
        if ($scheme !== 'https' && ! ($scheme === 'http' && $relaxed)) {
            throw new \InvalidArgumentException('Nur HTTPS ist zulaessig');
        }
        $port = (int) ($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        if ($port < 1 || $port > 65535) {
            throw new \InvalidArgumentException('Ungueltiger Port');
        }
        if ($relaxed) {
            return ['host' => $host, 'port' => $port, 'ip' => null, 'scheme' => $scheme];
        }

        $ips = filter_var($host, FILTER_VALIDATE_IP) ? [$host] : self::resolve($host);
        if ($ips === []) {
            throw new \InvalidArgumentException('Host nicht aufloesbar');
        }
        foreach ($ips as $ip) {
            if (! self::isPublic($ip)) {
                throw new \InvalidArgumentException('Zieladresse ist nicht zulaessig');
            }
        }

        return ['host' => $host, 'port' => $port, 'ip' => filter_var($host, FILTER_VALIDATE_IP) ? null : $ips[0], 'scheme' => $scheme];
    }

    public static function isPublic(string $ip): bool
    {
        if (str_starts_with(strtolower($ip), '::ffff:')) { // IPv4-mapped IPv6
            $ip = substr($ip, 7);
        }
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        if (strlen($bin) === 4) {
            $n = unpack('N', $bin)[1];
            // 100.64.0.0/10 (CGNAT), 192.0.0.0/24, 198.18.0.0/15, 224.0.0.0/4 (Multicast)
            foreach ([[0x64400000, 10], [0xC0000000, 24], [0xC6120000, 15], [0xE0000000, 4]] as [$net, $bits]) {
                $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
                if (($n & $mask) === $net) {
                    return false;
                }
            }
        } else {
            $first = ord($bin[0]);
            if ($first === 0xFF || ($first & 0xFE) === 0xFC || ($first === 0xFE && (ord($bin[1]) & 0xC0) === 0x80)) { // Multicast, ULA, Link-Local
                return false;
            }
        }

        return true;
    }

    /** @return list<string> */
    private static function resolve(string $host): array
    {
        $ips = [];
        foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $r) {
            $ips[] = $r['ip'] ?? $r['ipv6'] ?? null;
        }

        if ($ips === [] && function_exists('gethostbynamel')) {
            $ips = @gethostbynamel($host) ?: []; // Fallback fuer Hoster ohne dns_get_record
        }

        return array_values(array_filter($ips));
    }
}
