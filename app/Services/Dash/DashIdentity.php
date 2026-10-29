<?php

namespace App\Services\Dash;

/**
 * Validierte Identitaetsdaten aus Dash. Dash bleibt die fuehrende Quelle; log_in speichert keine Konten.
 */
final class DashIdentity
{
    public const STATUS_ACTIVE = 'active';

    /**
     * @param  list<string>  $roles
     * @param  array<string, mixed>  $extra
     */
    public function __construct(
        public readonly string $sub,
        public readonly string $status,
        public readonly ?string $name,
        public readonly ?string $email,
        public readonly bool $emailVerified,
        public readonly ?string $tenantId,
        public readonly array $roles,
        public readonly ?string $updatedAt,
    ) {}

    public function isActive(): bool
    {
        return $this->status === self::STATUS_ACTIVE;
    }

    /**
     * @param  array<string, mixed>  $d
     *
     * @throws DashProtocolException
     */
    public static function fromArray(array $d, string $expectedSub): self
    {
        $sub = $d['sub'] ?? null;
        if (! is_string($sub) || $sub === '' || strlen($sub) > 128 || ! hash_equals($expectedSub, $sub)) {
            throw new DashProtocolException('Identitaet passt nicht zur angefragten Subject-ID');
        }
        $status = $d['status'] ?? null;
        if (! in_array($status, ['active', 'disabled', 'locked', 'deleted'], true)) {
            throw new DashProtocolException('Unbekannter Kontostatus');
        }
        $roles = $d['roles'] ?? [];
        if (! is_array($roles)) {
            throw new DashProtocolException('Ungueltige Rollenliste');
        }
        foreach ($roles as $r) {
            if (! is_string($r) || ! preg_match('/^[a-z0-9][a-z0-9_.:\-]{0,63}$/i', $r)) {
                throw new DashProtocolException('Ungueltige Rolle');
            }
        }
        $tenant = $d['tenant_id'] ?? null;
        if ($tenant !== null && (! is_string($tenant) || strlen($tenant) > 128)) {
            throw new DashProtocolException('Ungueltige Mandanten-ID');
        }
        foreach (['name', 'email'] as $k) {
            if (isset($d[$k]) && (! is_string($d[$k]) || strlen($d[$k]) > 255)) {
                throw new DashProtocolException("Ungueltiges Feld $k");
            }
        }

        return new self($sub, $status, $d['name'] ?? null, $d['email'] ?? null, (bool) ($d['email_verified'] ?? false), $tenant, array_values($roles), isset($d['updated_at']) ? (string) $d['updated_at'] : null);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return get_object_vars($this);
    }
}
