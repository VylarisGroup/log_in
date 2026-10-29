<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Audit extends Model
{
    protected $table = 'audit_logs';

    public $timestamps = false;

    protected $guarded = [];

    protected $casts = ['context' => 'array', 'created_at' => 'datetime'];

    private const FORBIDDEN = ['password', 'secret', 'token', 'code', 'code_verifier', 'private', 'authorization', 'client_secret', 'mfa_code'];

    /** Schreibt einen Audit-Eintrag; sensible Schluessel werden nie protokolliert. */
    public static function log(string $event, ?string $actor = null, ?string $subject = null, array $context = []): void
    {
        $clean = [];
        foreach ($context as $k => $v) {
            $lk = strtolower((string) $k);
            foreach (self::FORBIDDEN as $f) {
                if (str_contains($lk, $f)) {
                    continue 2;
                }
            }
            $clean[$k] = is_scalar($v) || $v === null || is_array($v) ? $v : (string) $v;
        }
        static::query()->create([
            'event' => $event,
            'actor' => $actor,
            'subject' => $subject,
            'context' => $clean ?: null,
            'ip' => request()?->ip(),
        ]);
    }
}
