<?php

namespace App\Services\Oidc;

/** Anfragebezogener Zustand (ein Request = eine Instanz, als scoped Singleton registriert). */
class OidcContext
{
    public ?string $nonce = null;

    public ?string $sid = null;

    public ?int $authTime = null;

    public bool $issueIdToken = false;

    public ?string $userId = null;

    /** @var list<string> */
    public array $amr = [];

    public function reset(): void
    {
        $this->nonce = $this->sid = $this->authTime = $this->userId = null;
        $this->issueIdToken = false;
        $this->amr = [];
    }
}
