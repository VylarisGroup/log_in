<?php

namespace Tests\Feature;

use App\Services\Vylaris\UpdateService;
use App\Support\Version;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class UpdateServiceTest extends TestCase
{
    public function test_checksum_is_enforced(): void
    {
        $f = tempnam(sys_get_temp_dir(), 'z');
        file_put_contents($f, 'inhalt');
        $h = hash('sha256', 'inhalt');
        $u = new UpdateService;
        $u->verify($f, 'log_in-1.0.1.zip', "$h  log_in-1.0.1.zip\n", null); // ok
        $this->expectException(\RuntimeException::class);
        try {
            $u->verify($f, 'log_in-1.0.1.zip', str_repeat('0', 64)."  log_in-1.0.1.zip\n", null);
        } finally {
            File::delete($f);
        }
    }

    public function test_missing_checksum_entry_aborts(): void
    {
        $f = tempnam(sys_get_temp_dir(), 'z');
        file_put_contents($f, 'inhalt');
        $this->expectException(\RuntimeException::class);
        try {
            (new UpdateService)->verify($f, 'log_in-1.0.1.zip', hash('sha256', 'inhalt')."  anderes.zip\n", null);
        } finally {
            File::delete($f);
        }
    }

    public function test_version_scheme_parses_compares_and_rejects_foreign_tags(): void
    {
        $this->assertSame(['year' => 26, 'major' => 1, 'minor' => 2, 'fix' => 0], Version::parse('v26.01.0200'));
        $this->assertTrue(Version::compare('26.01.0201', '26.01.0200') > 0);
        $this->assertTrue(Version::compare('26.02.0000', '26.01.9920') > 0);
        $this->assertTrue(Version::compare('27.01.0000', '26.99.9920') > 0);
        $this->assertSame(0, Version::compare('v26.01.0200', '26.01.0200'));
        foreach (['1.1.0', '26.1.2', '26.00.0000', '26.01.0021', 'v26.01.02', 'abc'] as $bad) {
            $this->assertFalse(Version::isValid($bad), $bad);
        }
        $this->assertTrue(Version::compare('26.01.0200', '1.1.0') > 0); // alte Tags sind aelter
        $this->assertTrue(Version::isValid(config('vylaris.version')));
    }

    public function test_check_reads_latest_release_from_fixed_repository(): void
    {
        Http::fake(['api.github.com/repos/VylarisGroup/log_in/releases/latest' => Http::response([
            'tag_name' => 'v99.01.0000',
            'assets' => [['name' => 'log_in-99.01.0000.zip', 'browser_download_url' => 'https://github.com/x/a.zip'], ['name' => 'SHA256SUMS', 'browser_download_url' => 'https://github.com/x/s']],
        ])]);
        $i = (new UpdateService)->check();
        $this->assertTrue($i['update_available']);
        $this->assertSame('99.01.0000', $i['latest']);
        $this->assertSame('https://github.com/x/a.zip', $i['asset_url']);
        Http::assertSent(fn ($r) => str_starts_with($r->url(), 'https://api.github.com/repos/VylarisGroup/log_in/'));
    }
}
