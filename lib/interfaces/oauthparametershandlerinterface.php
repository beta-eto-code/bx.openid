<?php

namespace Bx\OpenId\interfaces;

use Bx\OpenId\OAuthParameters;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

interface OAuthParametersHandlerInterface
{
    public function updateGetConfigRequest(RequestInterface $request): void;
    public function updateGetConfigResponse(ResponseInterface $response): void;
}
