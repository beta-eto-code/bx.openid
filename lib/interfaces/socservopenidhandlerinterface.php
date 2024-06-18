<?php

namespace Bx\OpenId\interfaces;

use Bitrix\Main\HttpRequest;
use Bx\OpenId\SocServOpenId;
use Throwable;

interface SocServOpenIdHandlerInterface extends OAuthParametersHandlerInterface, OAuthTransportHandlerInterface
{
    public function getAuthorizeCode(SocServOpenId $socServOpenId, ?HttpRequest $request = null): ?string;
    public function getIdToken(SocServOpenId $socServOpenId, ?HttpRequest $request = null): ?string;
    public function saveUserAndGetId(array $externalUserData, SocServOpenId $socServOpenId): string;
    public function authorizeUser(string $userId, SocServOpenId $socServOpenId): void;
    public function handleExceptionAuthorize(Throwable $e): void;
}
