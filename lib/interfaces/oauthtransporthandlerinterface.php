<?php

namespace Bx\OpenId\interfaces;

use Bx\OpenId\OAuthTransport;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

interface OAuthTransportHandlerInterface
{
    public function updateExternalUserData(array $externalUserData, OAuthTransport $transport): array;
    public function updateGetAccessTokenRequest(RequestInterface $request, OAuthTransport $transport): void;
    public function updateGetAccessTokenResponse(ResponseInterface $response, OAuthTransport $transport): void;
    public function updateGetUserInfoRequest(RequestInterface $request, OAuthTransport $transport): void;
    public function updateGetUserInfoResponse(ResponseInterface $request, OAuthTransport $transport): void;
    public function getUrlForRedirect(OAuthTransport $transport): string;
}
