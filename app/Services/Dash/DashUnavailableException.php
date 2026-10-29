<?php

namespace App\Services\Dash;

/** Dash nicht erreichbar, Timeout oder 5xx. Aufrufer muessen geschlossen (fail closed) reagieren. */
class DashUnavailableException extends \RuntimeException {}
