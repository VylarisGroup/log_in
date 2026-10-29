<?php

namespace App\Services\Vylaris;

use App\Models\Audit;
use App\Support\Version;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;

/**
 * Updates ausschliesslich aus den GitHub-Releases von VylarisGroup/log_in (fest eingebaut, nicht konfigurierbar).
 * Ablauf: pruefen -> Backup -> Maintenance-Modus -> Release-Archiv laden -> SHA-256 gegen SHA256SUMS pruefen
 * (und Ed25519-Signatur, sobald ein Release-Schluessel hinterlegt ist) -> Dateien ersetzen (ohne .env, storage, database)
 * -> versionierte Migrationen -> Caches leeren -> Maintenance-Modus aus. Bei Fehler: Rollback der Dateien.
 */
class UpdateService
{
    public const REPO = 'VylarisGroup/log_in';

    /** Oeffentlicher Ed25519-Release-Schluessel (Base64). Leer = nur SHA-256-Pruefung (siehe docs/UPDATES.md). */
    public const RELEASE_PUBLIC_KEY = '';

    /** @return array{current: string, latest: ?string, tag: ?string, update_available: bool, asset_url: ?string, sums_url: ?string, sig_url: ?string} */
    public function check(): array
    {
        $res = Http::timeout(15)->withHeaders(['Accept' => 'application/vnd.github+json', 'User-Agent' => 'vylaris-log_in'])
            ->get('https://api.github.com/repos/'.self::REPO.'/releases/latest');
        if (! $res->ok()) {
            throw new \RuntimeException('GitHub-Releases nicht abrufbar (HTTP '.$res->status().')');
        }
        $tag = (string) $res->json('tag_name');
        $latest = Version::isValid($tag) ? ltrim($tag, 'v') : ''; // Tags ausserhalb des Schemas werden ignoriert
        $assets = collect($res->json('assets') ?? []);
        $url = fn (string $name) => $assets->firstWhere('name', $name)['browser_download_url'] ?? null;

        return [
            'current' => (string) config('vylaris.version'),
            'latest' => $latest ?: null,
            'tag' => $tag ?: null,
            'update_available' => $latest !== '' && Version::compare($latest, Version::current()) > 0,
            'asset_url' => $url("log_in-{$latest}.zip"),
            'sums_url' => $url('SHA256SUMS'),
            'sig_url' => $url('SHA256SUMS.sig'),
        ];
    }

    /** @param  callable(string):void  $log */
    public function apply(callable $log): void
    {
        $info = $this->check();
        if (! $info['update_available']) {
            $log('Bereits aktuell ('.$info['current'].').');

            return;
        }
        if ($info['asset_url'] === null || $info['sums_url'] === null) {
            throw new \RuntimeException('Release enthaelt kein log_in-<version>.zip oder SHA256SUMS.');
        }
        $work = storage_path('app/update-'.bin2hex(random_bytes(4)));
        File::ensureDirectoryExists($work, 0700);
        try {
            $log('Backup ...');
            Artisan::call('login:backup', ['--keep' => 14]);

            $log('Lade '.$info['asset_url']);
            $zip = $work.'/release.zip';
            $dl = Http::timeout(120)->withHeaders(['User-Agent' => 'vylaris-log_in'])->sink($zip)->get($info['asset_url']);
            if (! $dl->ok()) {
                throw new \RuntimeException('Download fehlgeschlagen (HTTP '.$dl->status().')');
            }
            $sums = Http::timeout(30)->get($info['sums_url'])->body();
            $this->verify($zip, "log_in-{$info['latest']}.zip", $sums, $info['sig_url']);
            $log('Pruefsumme'.(self::RELEASE_PUBLIC_KEY !== '' ? ' und Signatur' : '').' OK.');

            $za = new \ZipArchive;
            if ($za->open($zip) !== true) {
                throw new \RuntimeException('Archiv nicht lesbar');
            }
            $stage = $work.'/new';
            foreach (range(0, $za->numFiles - 1) as $i) {
                $name = $za->getNameIndex($i);
                if (str_contains($name, '..') || str_starts_with($name, '/') || str_contains($name, "\0")) {
                    throw new \RuntimeException('Unsicherer Pfad im Archiv: '.$name);
                }
            }
            $za->extractTo($stage);
            $za->close();
            $root = is_file($stage.'/artisan') ? $stage : (File::directories($stage)[0] ?? $stage);
            if (! is_file($root.'/artisan')) {
                throw new \RuntimeException('Archiv enthaelt kein log_in-Projekt');
            }

            Artisan::call('down', ['--retry' => 30]);
            $log('Maintenance-Modus an.');
            $rollback = $work.'/rollback';
            $this->swap($root, base_path(), $rollback, $log);
            try {
                Artisan::call('migrate', ['--force' => true]);
                $log('Migrationen ausgefuehrt.');
            } catch (\Throwable $e) {
                $log('Migration fehlgeschlagen - Dateien werden zurueckgesetzt: '.$e->getMessage());
                $this->restore($rollback, base_path());
                throw $e;
            } finally {
                Artisan::call('optimize:clear');
                Artisan::call('up');
            }
            Audit::log('update.applied', 'cli', null, ['from' => $info['current'], 'to' => $info['latest']]);
            $log('Update auf '.$info['latest'].' abgeschlossen. Datenbank-Rollback bei Bedarf: php artisan login:restore <backup>');
        } finally {
            File::deleteDirectory($work);
        }
    }

    /** @throws \RuntimeException */
    public function verify(string $zipPath, string $assetName, string $sums, ?string $sigUrl): void
    {
        $expected = null;
        foreach (preg_split('/\R/', $sums) as $line) {
            if (preg_match('/^([a-f0-9]{64})\s+\*?(.+)$/i', trim($line), $m) && $m[2] === $assetName) {
                $expected = strtolower($m[1]);
            }
        }
        if ($expected === null || ! hash_equals($expected, hash_file('sha256', $zipPath))) {
            throw new \RuntimeException('SHA-256-Pruefsumme stimmt nicht - Update abgebrochen.');
        }
        if (self::RELEASE_PUBLIC_KEY !== '') {
            $sig = $sigUrl === null ? '' : trim(Http::timeout(30)->get($sigUrl)->body());
            if (! Signer::verify($sums, $sig, self::RELEASE_PUBLIC_KEY)) {
                throw new \RuntimeException('Release-Signatur ungueltig - Update abgebrochen.');
            }
        }
    }

    /** Ersetzt Programmdateien; .env, storage/, database/*.sqlite, vendor-Cache und Backups bleiben unberuehrt. */
    private function swap(string $from, string $to, string $rollback, callable $log): void
    {
        $keep = ['.env', 'storage', '.git', 'database/database.sqlite'];
        File::ensureDirectoryExists($rollback);
        foreach (File::allFiles($from, true) as $f) {
            $rel = $f->getRelativePathname();
            foreach ($keep as $k) {
                if ($rel === $k || str_starts_with($rel, $k.'/')) {
                    continue 2;
                }
            }
            $dest = $to.'/'.$rel;
            if (File::exists($dest)) {
                File::ensureDirectoryExists(dirname($rollback.'/'.$rel));
                File::copy($dest, $rollback.'/'.$rel);
            }
            File::ensureDirectoryExists(dirname($dest));
            File::copy($f->getPathname(), $dest);
        }
        $log('Dateien ersetzt.');
    }

    private function restore(string $rollback, string $to): void
    {
        if (! is_dir($rollback)) {
            return;
        }
        foreach (File::allFiles($rollback, true) as $f) {
            File::copy($f->getPathname(), $to.'/'.$f->getRelativePathname());
        }
    }
}
