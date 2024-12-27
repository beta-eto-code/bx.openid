<?php

namespace Bx\OpenId;

use Bitrix\Main\ArgumentException;
use Bitrix\Main\Web\Json;
use Bitrix\Main\Web\JWT;
use Bitrix\Socialservices\OAuth\StateService;
use Bx\OpenId\interfaces\OAuthTransportHandlerInterface;
use CSocServAuthManager;
use CSocServOAuthTransport;
use CUtil;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Throwable;

class OAuthTransport extends CSocServOAuthTransport
{
    public const MODE_CODE_FLOW = 'code';
    public const MODE_IMPLICIT_FLOW = 'implicit';

    private OAuthParameters $authParameters;
    private string $mode;
    private ?string $idToken;
    private string $socServiceId;
    private ?ClientInterface $httpClient;
    private ?OAuthTransportHandlerInterface $authHandler;
    private ?LoggerInterface $logger;

    public function __construct(
        string $socServiceId,
        OAuthParameters $authParameters,
        ?string $code = null,
        ?string $idToken = null,
        ?string $mode = null,
        ?OAuthTransportHandlerInterface $authHandler = null,
        ?ClientInterface $httpClient = null,
        ?LoggerInterface $logger = null
    ) {
        parent::__construct($authParameters->applicationId, $authParameters->applicationSecret, $code);
        $this->socServiceId = $socServiceId;
        $this->idToken = $idToken;
        $this->authParameters = $authParameters;
        $this->scope = explode(' ', $this->authParameters->scope);
        $this->mode = $mode === static::MODE_IMPLICIT_FLOW ? static::MODE_IMPLICIT_FLOW : static::MODE_CODE_FLOW;
        $this->authHandler = $authHandler;
        $this->httpClient = $httpClient;
        $this->logger = $logger;
    }

    public function setHandler(OAuthTransportHandlerInterface $authHandler): void
    {
        $this->authHandler = $authHandler;
    }

    public function getAuthParameters(): OAuthParameters
    {
        return $this->authParameters;
    }

    public function setIdToken(string $idToken): void
    {
        $this->idToken = $idToken;
    }

    /**
     * @throws Throwable
     */
    public function getUserData(bool $useUserInfoUrl = false): array
    {
        $data = [];
        if (!empty($this->code)) {
            $accessToken = $this->getAccessToken();
            $data = array_merge($data, $this->getDecodedDataFromJwt($accessToken));
        }

        if (!empty($this->idToken)) {
            $data = array_merge($data, $this->getDecodedDataFromJwt($this->idToken));
        }

        if ($useUserInfoUrl) {
            $data = array_merge($data, $this->getUserInfo());
        }

        return !empty($this->authHandler) ? $this->authHandler->updateExternalUserData($data, $this) : $data;
    }

    /**
     * @throws Throwable
     */
    private function getDecodedDataFromJwt(string $jwt): array
    {
        $exception = new Exception('Отсуствует публичный ключ');
        foreach ($this->authParameters->publicKeys as $publicKey) {
            try {
                $object = JWT::decode($jwt, $publicKey, $this->authParameters->signingAlg);
                return json_decode(json_encode($object), true);
            } catch (Throwable $e) {
                $exception = $e;
            }
        }
        throw $exception;
    }

    public function redirectUser(): void
    {
        global $APPLICATION;
        $APPLICATION->RestartBuffer();
        $redirectUrl = $this->getUrlForRedirect();
        ?>
        <script type="text/javascript">
            if (window.opener)
                window.opener.location = '<?=CUtil::JSEscape($redirectUrl)?>';
            window.close();
        </script>
        <?php
        die();
    }

    public function getUrlForRedirect(): string
    {
        if (!empty($this->authHandler)) {
            return $this->authHandler->getUrlForRedirect($this);
        }

        [
            $url,
            $query
        ] = $this->getRedirectUrlParts();
        return $url . '?' . $this->getQueryForRedirectUrl($query);
    }

    private function getRedirectUrlParts(): array
    {
        $urlParts = explode('?', $this->authParameters->authUrl);
        $query = [];
        parse_str($urlParts[1] ?? '', $query);
        return [
            $urlParts[0] ?? '',
            $query
        ];
    }

    private function getQueryForRedirectUrl(array $query): string
    {
        $isImplicitFlow = $this->isImplicitFlow();
        $query = array_merge($query, [
            'response_type' => $isImplicitFlow ? 'id_token' : 'code',
            'client_id' => $this->authParameters->applicationId,
            'scope' => $this->authParameters->scope,
            'redirect_uri' => $this->authParameters->redirectUrl,
            'nonce' => $this->getNonce(),
            'state' => $this->createState()
        ]);
        return http_build_query($query);
    }

    private function isImplicitFlow(): bool
    {
        return $this->mode === static::MODE_IMPLICIT_FLOW;
    }

    public function getNonce(): string
    {
        return md5('nonce_' . $this->getUniqueKey());
    }


    public function createState(): string
    {
        global $APPLICATION;
        $backUrl = $_GET['backurl'] ?? $APPLICATION->GetCurPageParam(
            '',
            ["logout", "auth_service_error", "auth_service_id", "backurl"]
        );

        return $this->state = StateService::getInstance()->createState([
            'check_key' => $this->getUniqueKey(),
            'backurl' => $backUrl,
            'serviceId' => $this->socServiceId
        ]);
    }

    private function getUniqueKey(): string
    {
        return CSocServAuthManager::GetUniqueKey();
    }

    /**
     * @throws Exception
     * @throws ClientExceptionInterface
     */
    public function getAccessToken(): string
    {
        if (!empty($this->access_token)) {
            return (string) $this->access_token;
        }

        if (empty($this->code)) {
            throw new Exception('Код авторизации пуст');
        }

        $this->logMessage('getAccessToken');
        $requestBody = http_build_query([
            'client_id' => $this->authParameters->applicationId,
            'client_secret' => $this->authParameters->applicationSecret,
            'code' => $this->code,
            'redirect_uri' => $this->authParameters->redirectUrl,
            'grant_type' => 'authorization_code'
        ]);

        $hasHandler = !empty($this->authHandler);
        $request = new Request(
            'POST',
            $this->authParameters->tokenUrl,
            [
                'Content-type' => 'application/x-www-form-urlencoded',
            ],
            $requestBody
        );

        $this->logRequest($request);
        if ($hasHandler) {
            $this->authHandler->updateGetAccessTokenRequest($request, $this);
        }

        $response = $this->getHttpClient()->sendRequest($request);
        $this->logResponse($response);
        if ($hasHandler) {
            $this->authHandler->updateGetAccessTokenResponse($response, $this);
        }

        $data = $this->getParsedJsonDataFromResponse($response);
        $this->access_token = $data['access_token']  ?: null;
        $this->refresh_token = $data['refresh_token']  ?: null;
        $this->idToken = $data['id_token']  ?: null;
        return $this->access_token ?: '';
    }

    /**
     * @throws Exception
     * @throws ClientExceptionInterface
     */
    private function getUserInfo(): array
    {
        $this->logMessage('getUserInfo');
        $request = new Request('GET', $this->authParameters->userInfoUrl, [
            'headers' => [
                'Authorization' => 'Bearer ' . $this->getAccessToken()
            ]
        ]);

        $this->logRequest($request);
        $hasHandler = !empty($this->authHandler);
        if ($hasHandler) {
            $this->authHandler->updateGetUserInfoRequest($request, $this);
        }

        $response = $this->getHttpClient()->sendRequest($request);
        $this->logResponse($response);
        if ($hasHandler) {
            $this->authHandler->updateGetUserInfoResponse($response, $this);
        }

        return $this->getParsedJsonDataFromResponse($response);
    }

    /**
     * @throws ArgumentException
     * @throws Exception
     */
    private function getParsedJsonDataFromResponse(ResponseInterface $response): array
    {
        $responseBody = (string) $response->getBody();
        $statusCode = $response->getStatusCode();
        if ($statusCode >= 400) {
            throw new Exception("HTTP error ($statusCode): $responseBody");
        }

        return Json::decode($responseBody);
    }

    private function getHttpClient(): ClientInterface
    {
        if (empty($this->httpClient)) {
            $this->httpClient = new Client();
        }

        return $this->httpClient;
    }

    private function logRequest(RequestInterface $request): void
    {
        if (empty($this->logger)) {
            return;
        }

        $newRequest = clone $request;
        $body = $newRequest->getBody();
        $this->logMessage('HTTP request: ' . json_encode([
                'headers' => $newRequest->getHeaders(),
                'body' => $body->getContents(),
            ], JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
    }

    private function logResponse(ResponseInterface $response): void
    {
        if (empty($this->logger)) {
            return;
        }

        $newResponse = clone $response;
        $body = $newResponse->getBody();
        $this->logMessage('HTTP response: ' . json_encode([
                'statusCode' => $newResponse->getStatusCode(),
                'headers' => $newResponse->getHeaders(),
                'body' => $body->getContents(),
            ], JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
    }

    private function logMessage(string $message): void
    {
        $this->logger?->info($message);
    }
}
