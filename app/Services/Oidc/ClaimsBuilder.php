<?php

namespace App\Services\Oidc;

use App\Services\Dash\DashIdentity;

/** Datensparsame Claims: nur was die gewaehrten Scopes erlauben. */
final class ClaimsBuilder
{
    /**
     * @param  list<string>  $scopes
     * @return array<string, mixed>
     */
    public static function forScopes(DashIdentity $i, array $scopes): array
    {
        $c = [];
        if (in_array('profile', $scopes, true) && $i->name !== null) {
            $c['name'] = $i->name;
        }
        if (in_array('email', $scopes, true) && $i->email !== null) {
            $c['email'] = $i->email;
            $c['email_verified'] = $i->emailVerified;
        }
        if (in_array('vylaris', $scopes, true)) {
            $c['tenant_id'] = $i->tenantId;
            $c['roles'] = $i->roles;
        }

        return $c;
    }
}
