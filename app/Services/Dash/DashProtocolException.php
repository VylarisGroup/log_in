<?php

namespace App\Services\Dash;

/** Antwort verletzt den Vertrag (fehlende/ungueltige Signatur, ungueltiges Schema, falsche Identitaet). */
class DashProtocolException extends \RuntimeException {}
