<?php

namespace Tests\Feature;

use App\Services\Vylaris\UpdateService;
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

    public function test_check_reads_latest_release_from_fixed_repository(): void
    {
        Http::fake(['api.github.com/repos/VylarisGroup/log_in/releases/latest' => Http::response([
            'tag_name' => 'v9.9.9',
            'assets' => [['name' => 'log_in-9.9.9.zip', 'browser_download_url' => 'https://github.com/x/a.zip'], ['name' => 'SHA256SUMS', 'browser_download_url' => 'https://github.com/x/s']],
        ])]);
        $i = (new UpdateService)->check();
        $this->assertTrue($i['update_available']);
        $this->assertSame('9.9.9', $i['latest']);
        $this->assertSame('https://github.com/x/a.zip', $i['asset_url']);
        Http::assertSent(fn ($r) => str_starts_with($r->url(), 'https://api.github.com/repos/VylarisGroup/log_in/'));
    }
}
