<?php

namespace Bx\OpenId;

use Bitrix\Main\Web\JWK;
use Bx\OpenId\interfaces\OAuthParametersHandlerInterface;
use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

class OAuthParameters
{
    public string $applicationId = '';
    public string $applicationSecret = '';
    public string $redirectUrl = '';
    public string $scope = '';
    public string $authUrl = '';
    public string $tokenUrl = '';
    public string $userInfoUrl = '';
    public string $jwksUrl = '';
    public string $logoutUrl = '';
    /**
     * @var string[]
     */
    public array $publicKeys = [];

    public array $signingAlg = ['HS256', 'ES256', 'RS256'];
    
    private static ?ClientInterface $httpClient = null;

    /**
     * @throws InvalidArgumentException
     * @throws Exception|ClientExceptionInterface
     */
    static public function initFromConfigUrlWithCache(
        string $configUrl,
        CacheInterface $cache,
        ?string $applicationId = null,
        ?string $applicationSecret = null,
        ?string $redirectUrl = null,
        ?OAuthParametersHandlerInterface $handler = null,
        ?ClientInterface $httpClient = null
    ): OAuthParameters {
        $configData = static::getDataByUrlWithCache(
            $configUrl,
            'Файл конфигурации OAuth пуст',
            $cache,
            'configUrl_' . $configUrl,
            $handler,
            $httpClient
        );
        return static::initFromConfigData($configData, $applicationId, $applicationSecret, $redirectUrl);
    }

    /**
     * @throws Exception
     * @throws ClientExceptionInterface
     */
    static public function initFromConfigUrl(
        string $configUrl,
        ?string $applicationId = null,
        ?string $applicationSecret = null,
        ?string $redirectUrl = null,
        ?OAuthParametersHandlerInterface $handler = null,
        ?ClientInterface $httpClient = null
    ): OAuthParameters {
        $configData = static::getDataByUrl(
            $configUrl,
            'Файл конфигурации OAuth пуст',
            $handler,
            $httpClient
        );
        return static::initFromConfigData($configData, $applicationId, $applicationSecret, $redirectUrl);
    }

    /**
     * @throws Exception|ClientExceptionInterface
     */
    static private function initFromConfigData(
        string $configData,
        ?string $applicationId = null,
        ?string $applicationSecret = null,
        ?string $redirectUrl = null
    ): OAuthParameters {
        $config = json_decode($configData, true);
        if (empty($config)) {
            throw new Exception('Файл конфигурации OAuth пуст');
        }

        $oauthParameters = new OAuthParameters();
        $oauthParameters->applicationId = $applicationId ?? '';
        $oauthParameters->applicationSecret = $applicationSecret ?? '';
        $oauthParameters->redirectUrl = $redirectUrl ?? '';
        $oauthParameters->authUrl = $config['authorization_endpoint'] ?? '';
        $oauthParameters->tokenUrl = $config['token_endpoint'] ?? '';
        $oauthParameters->userInfoUrl = $config['userinfo_endpoint'] ?? '';
        $oauthParameters->logoutUrl = $config['end_session_endpoint'] ?? '';
        $oauthParameters->jwksUrl = $config['jwks_uri'] ?? '';
        $oauthParameters->signingAlg = static::getSigningAlgByConfig($config) ?: $oauthParameters->signingAlg;
        $oauthParameters->loadJwks();
        return $oauthParameters;
    }

    /**
     * @throws Exception
     * @throws InvalidArgumentException|ClientExceptionInterface
     */
    public function loadJwksWithCache(CacheInterface $cache): void
    {
        if (empty($this->jwksUrl)) {
            return;
        }

        $jwksData = static::getDataByUrlWithCache(
            $this->jwksUrl,
            'Файл jwks пуст',
            $cache, 'jwks_' . $this->jwksUrl
        );
        $this->parseJwksDataAndLoadKeys($jwksData);
    }

    /**
     * @throws Exception
     * @throws InvalidArgumentException|ClientExceptionInterface
     */
    static private function getDataByUrlWithCache(
        string $url,
        string $exceptionEmptyData,
        CacheInterface $cache,
        ?string $cacheKey,
        ?OAuthParametersHandlerInterface $handler = null,
        ?ClientInterface $httpClient = null
    ): string {
        $key = md5($cacheKey ?? "url_" . $url);
        $data = $cache->get($key);
        if (is_array($data)) {
            $data = json_encode($data);
        }

        if (!empty($data)) {
            return $data;
        }

        $data = static::getDataByUrl($url, $exceptionEmptyData, $handler, $httpClient);
        $cache->set($key, $data);
        return $data;
    }

    /**
     * @throws Exception|ClientExceptionInterface
     */
    public function loadJwks(?ClientInterface $httpClient = null): void
    {
        if (empty($this->jwksUrl)) {
            return;
        }

        $jwksData = $this->getDataByUrl($this->jwksUrl, 'Файл jwks пуст', $httpClient);
        $this->parseJwksDataAndLoadKeys($jwksData);
    }

    /**
     * @throws Exception
     * @throws ClientExceptionInterface
     */
    static private function getDataByUrl(
        string $url,
        string $exceptionEmptyData,
        ?OAuthParametersHandlerInterface $handler = null,
        ?ClientInterface $httpClient = null
    ): string {
        $httpClient = $httpClient ?? static::getHttpClient();
        $request = new Request('GET', $url);
        if (!empty($handler)) {
            $handler->updateGetConfigRequest($request);
        }
        $response = $httpClient->sendRequest($request);
        if (!empty($handler)) {
            $handler->updateGetConfigResponse($response);
        }

        $responseBody = (string) $response->getBody();
        $statusCode = $response->getStatusCode();
        if ($statusCode >= 400) {
            throw new Exception("HTTP error ($statusCode): $responseBody");
        }

        if (empty($responseBody)) {
            throw new Exception($exceptionEmptyData);
        }

        return $responseBody;
    }

    private function parseJwksDataAndLoadKeys(string $jwksData): void
    {
        $jwks = json_decode($jwksData, true);
        $rawKeysData = $jwks['keys'] ?? [];
        if (empty($rawKeysData)) {
            return;
        }

        $this->publicKeys = [];
        foreach ($rawKeysData as $keyData) {
            $this->publicKeys[] = JWK::parseKey($keyData);
        }
    }

    static private function getSigningAlgByConfig(array $config): array
    {
        $signingAlgKeys = [
            'id_token_signing_alg_values_supported',
            'token_endpoint_auth_signing_alg_values_supported',
            'userinfo_signing_alg_values_supported',
            'request_object_signing_alg_values_supported',
            'token_endpoint_auth_signing_alg_values_supported',
            'authorization_signing_alg_values_supported',
        ];

        foreach ($signingAlgKeys as $key) {
            $signingAlg = $config[$key] ?? [];
            if (!empty($signingAlg)) {
                return $signingAlg;
            }
        }

        return [];
    }

    private static function getHttpClient(): ClientInterface
    {
        if (empty(static::$httpClient)) {
            static::$httpClient = new Client();
        }
        return static::$httpClient;
    }
}
