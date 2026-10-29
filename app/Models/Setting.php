<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Crypt;

class Setting extends Model
{
    protected $primaryKey = 'key';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    public static function get(string $key, ?string $default = null): ?string
    {
        return static::query()->find($key)?->value ?? $default;
    }

    public static function put(string $key, ?string $value): void
    {
        static::query()->updateOrCreate(['key' => $key], ['value' => $value]);
    }

    public static function getSecret(string $key): ?string
    {
        $v = static::get($key);

        return $v === null ? null : Crypt::decryptString($v);
    }

    public static function putSecret(string $key, string $value): void
    {
        static::put($key, Crypt::encryptString($value));
    }

    public static function forget(string $key): void
    {
        static::query()->whereKey($key)->delete();
    }
}
