<?php

namespace Bx\OpenId;

use Bitrix\Main\ArgumentException;
use Bitrix\Main\HttpRequest;
use Bitrix\Main\ObjectPropertyException;
use Bitrix\Main\SystemException;
use Bx\OpenId\interfaces\SocServOpenIdHandlerInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

abstract class BaseSocServiceHandler implements SocServOpenIdHandlerInterface
{
    public function updateGetConfigRequest(RequestInterface $request): void
    {
        return;
    }

    public function updateGetConfigResponse(ResponseInterface $response): void
    {
        return;
    }

    public function updateExternalUserData(array $externalUserData, OAuthTransport $transport): array
    {
        return $externalUserData;
    }

    public function updateGetAccessTokenRequest(RequestInterface $request, OAuthTransport $transport): void
    {
        return;
    }

    public function updateGetAccessTokenResponse(ResponseInterface $response, OAuthTransport $transport): void
    {
        return;
    }

    public function updateGetUserInfoRequest(RequestInterface $request, OAuthTransport $transport): void
    {
        return;
    }

    public function updateGetUserInfoResponse(ResponseInterface $request, OAuthTransport $transport): void
    {
        return;
    }

    public function getUrlForRedirect(OAuthTransport $transport): string
    {
        return $transport->getUrlForRedirect();
    }

    public function getAuthorizeCode(SocServOpenId $socServOpenId, ?HttpRequest $request = null): ?string
    {
        return $socServOpenId->getAuthorizeCode($request);
    }

    public function getIdToken(SocServOpenId $socServOpenId, ?HttpRequest $request = null): ?string
    {
        return $socServOpenId->getIdToken($request);
    }

    /**
     * @throws Throwable
     * @throws ArgumentException
     * @throws ObjectPropertyException
     * @throws SystemException
     */
    public function saveUserAndGetId(array $externalUserData, SocServOpenId $socServOpenId): string
    {
        return $socServOpenId->saveUserAndGetId($externalUserData);
    }

    public function authorizeUser(string $userId, SocServOpenId $socServOpenId): void
    {
        $socServOpenId->internalAuthorizeUser($userId);
    }

    public function handleExceptionAuthorize(Throwable $e): void
    {
        return;
    }
}