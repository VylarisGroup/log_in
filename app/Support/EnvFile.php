<?php

namespace App\Support;

/**
 * Minimaler, sicherer Schreibzugriff auf die .env-Datei (fuer den Web-Installer).
 * Werte duerfen keine Zeilenumbrueche enthalten; Sonderzeichen werden in doppelte Anfuehrungszeichen gesetzt.
 */
final class EnvFile
{
    public static function path(): string
    {
        return (string) (config('vylaris.env_path') ?: base_path('.env'));
    }

    /** @param  array<string, string>  $values */
    public static function set(array $values, ?string $path = null): void
    {
        $path ??= self::path();
        $content = is_file($path) ? (string) file_get_contents($path) : '';
        foreach ($values as $key => $value) {
            if (! preg_match('/^[A-Z][A-Z0-9_]*$/', $key) || preg_match('/[\r\n\0]/', $value)) {
                throw new \InvalidArgumentException('Ungueltiger Konfigurationswert fuer '.$key);
            }
            $line = $key.'='.self::quote($value);
            $pattern = '/^'.preg_quote($key, '/').'=.*$/m';
            if (preg_match($pattern, $content)) {
                $content = (string) preg_replace_callback($pattern, fn () => $line, $content, 1);
            } else {
                $content = rtrim($content, "\n")."\n".$line."\n";
            }
        }
        if (@file_put_contents($path, $content, LOCK_EX) === false) {
            throw new \RuntimeException('Die Datei .env ist nicht beschreibbar.');
        }
        @chmod($path, 0600);
    }

    private static function quote(string $v): string
    {
        if ($v === '' || preg_match('/^[A-Za-z0-9_.:\/@+=\-]+$/', $v)) {
            return $v;
        }

        return '"'.str_replace(['\\', '"', '$'], ['\\\\', '\\"', '\\$'], $v).'"';
    }

    /**
     * Erzeugt beim ersten Aufruf ueber das Web eine lauffaehige .env (oder ergaenzt einen fehlenden APP_KEY).
     * Standard: SQLite (keine Datenbank-Zugangsdaten noetig), Datei-Sessions/-Cache, Pseudo-Cron.
     * Die Werte koennen im Installer geaendert werden.
     */
    public static function provision(string $basePath, string $host, bool $https): void
    {
        $envPath = $basePath.'/.env';
        $current = is_file($envPath) ? (string) file_get_contents($envPath) : null;
        if ($current !== null && preg_match('/^APP_KEY=\S+/m', $current)) {
            return;
        }
        if ($current === null) {
            $example = $basePath.'/.env.example';
            if (! is_file($example) || ! @copy($example, $envPath)) {
                return; // nicht beschreibbar: der Installer zeigt eine verstaendliche Meldung
            }
        }
        $host = preg_replace('/[^A-Za-z0-9.\-:\[\]]/', '', $host) ?: 'localhost';
        $url = ($https ? 'https://' : 'http://').$host;
        $sqlite = $basePath.'/database/database.sqlite';
        if (! is_file($sqlite)) {
            @touch($sqlite);
        }
        $vals = [
            'APP_KEY' => 'base64:'.base64_encode(random_bytes(32)),
            'APP_URL' => $url,
            'OIDC_ISSUER' => $url,
        ];
        // Vor der Migration existiert noch keine Sessions-Tabelle: Datei-Sessions/-Cache sind der sichere Startzustand.
        $vals += ['SESSION_DRIVER' => 'file', 'CACHE_STORE' => 'file', 'SESSION_SECURE_COOKIE' => $https ? 'true' : 'false'];
        if ($current === null) {
            $vals += ['DB_CONNECTION' => 'sqlite', 'DB_DATABASE' => $sqlite, 'PSEUDO_CRON' => 'true'];
        }
        self::set($vals, $envPath);
    }
}
