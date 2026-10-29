<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class OidcClient extends Model
{
    protected $primaryKey = 'client_id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    protected $hidden = ['secret_hash', 'previous_secret_hash'];

    protected $casts = [
        'redirect_uris' => 'array',
        'post_logout_uris' => 'array',
        'scopes' => 'array',
        'confidential' => 'boolean',
        'is_dash' => 'boolean',
        'previous_secret_until' => 'datetime',
        'disconnected_at' => 'datetime',
    ];

    public function isUsable(): bool
    {
        return $this->status === 'active';
    }

    public static function hashSecret(string $secret): string
    {
        return hash('sha256', $secret);
    }

    public function secretMatches(string $secret): bool
    {
        $h = self::hashSecret($secret);
        if ($this->secret_hash !== null && hash_equals($this->secret_hash, $h)) {
            return true;
        }

        return $this->previous_secret_hash !== null
            && $this->previous_secret_until !== null
            && $this->previous_secret_until->isFuture()
            && hash_equals($this->previous_secret_hash, $h);
    }

    /** Statusdarstellung fuer die Dash-Kachel. */
    public function toTile(): array
    {
        return [
            'client_id' => $this->client_id,
            'installation_id' => $this->installation_id,
            'tool_id' => $this->tool_id,
            'name' => $this->name,
            'base_url' => $this->base_url,
            'domain' => $this->domain,
            'version' => $this->version,
            'status' => $this->status,
            'confidential' => $this->confidential,
            'redirect_uris' => $this->redirect_uris,
            'post_logout_uris' => $this->post_logout_uris ?? [],
            'scopes' => $this->scopes,
            'last_error' => $this->last_error,
            'updated_at' => $this->updated_at?->toIso8601String(),
        ];
    }
}
