<?php

namespace Bx\OpenId;

use Bx\OpenId\interfaces\SocServOpenIdHandlerInterface;

class SocServKeycloak extends SocServOpenId
{
    private static ?SocServOpenIdHandlerInterface $handler = null;

    static public function getId(): string
    {
        return 'Keycloak';
    }

    static public function getName(): string
    {
        return 'Keycloak (Loodsen)';
    }

    static public function getIconCode(): string
    {
        return 'keycloak';
    }

    static public function getHandler(): ?SocServOpenIdHandlerInterface
    {
        return static::$handler;
    }

    static public function setHandler(SocServOpenIdHandlerInterface $handler): void
    {
        static::$handler = $handler;
    }
}
