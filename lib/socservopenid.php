<?php

namespace Bx\OpenId;

use Bitrix\Main\Application;
use Bitrix\Main\ArgumentException;
use Bitrix\Main\Context;
use Bitrix\Main\EventManager;
use Bitrix\Main\GroupTable;
use Bitrix\Main\HttpRequest;
use Bitrix\Main\LoaderException;
use Bitrix\Main\ObjectPropertyException;
use Bitrix\Main\ORM\Fields\ExpressionField;
use Bitrix\Main\Security\Random;
use Bitrix\Main\SystemException;
use Bitrix\Main\UserGroupTable;
use Bitrix\Main\UserTable;
use BitrixPSR16\Cache;
use Bx\Logger\SimpleTextLogger;
use Bx\OpenId\interfaces\SocServOpenIdHandlerInterface;
use CSocServAuth;
use CSocServAuthManager;
use CUser;
use CUtil;
use Exception;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;
use Throwable;

abstract class SocServOpenId extends CSocServAuth
{
    public const CONFIG_CLIENT_ID = 'openid_client_id';
    public const CONFIG_CLIENT_SECRET = 'openid_secret';
    public const CONFIG_URL_REDIRECT = 'openid_url_redirect';
    public const CONFIG_SCOPE = 'openid_scope';
    public const CONFIG_GRANT_TYPE = 'openid_grant_type';
    public const CONFIG_USE_USER_INFO_URL = 'openid_use_user_info_url';
    public const CONFIG_USE_CONFIG_URL = 'openid_use_config_url';
    public const CONFIG_URL_CONFIG = 'openid_url_config';
    public const CONFIG_CONFIG_TTL = 'openid_config_ttl';
    public const CONFIG_USER_EXTERNAL_KEY = 'openid_external_key';
    public const CONFIG_USER_INTERNAL_KEY = 'openid_internal_key';
    public const CONFIG_IGNORE_CASE = 'openid_ignore_case';
    public const CONFIG_USER_NAME_KEY = 'openid_name_key';
    public const CONFIG_USER_SECOND_NAME_KEY = 'openid_second_name_key';
    public const CONFIG_USER_LAST_NAME_KEY = 'openid_last_name_key';
    public const CONFIG_USER_EMAIL_KEY = 'openid_email_key';
    public const CONFIG_ALLOW_CREATE_USER = 'openid_allow_create_user';
    public const CONFIG_ALLOW_UPDATE_USER = 'openid_allow_update_user';
    public const CONFIG_USER_GROUPS = 'openid_user_groups';

    public const CONFIG_AUTH_URL = 'openid_auth_url';
    public const CONFIG_TOKEN_URL = 'openid_token_url';
    public const CONFIG_USER_INFO_URL = 'openid_user_info_url';
    public const CONFIG_LOGOUT_URL = 'openid_logout_url';
    public const CONFIG_SIGNING_ALG = 'openid_signing_alg';
    public const CONFIG_JWKS_URL = 'openid_jwks_url';
    public const CONFIG_PUBLIC_KEY = 'openid_public_key';
    public const CONFIG_USE_LOGGING = 'use_logging';
    public const CONFIG_LOG_DIR = 'log_dir';

    protected ?LoggerInterface $logger;
    private ?OAuthTransport $transport;
    private ?SocServOpenIdHandlerInterface $handler;

    abstract static public function getId(): string;
    abstract static public function getName(): string;
    abstract static public function getIconCode(): string;
    abstract static public function getHandler(): ?SocServOpenIdHandlerInterface;

    abstract static public function setHandler(SocServOpenIdHandlerInterface $handler): void;

    static public function createNewService(
        string $id,
        string $name,
        string $iconCode,
               $userId = null,
        ?SocServOpenIdHandlerInterface $handler = null,
        ?OAuthTransport $transport = null,
        ?LoggerInterface $logger = null
    ): SocServOpenId {
        $newService = new class ($userId, $transport, $logger) extends SocServOpenId {
            static string $id = '';
            static string $name = '';
            static string $iconCode = '';
            static ?SocServOpenIdHandlerInterface $handler = null;

            static public function getId(): string
            {
                return static::$id;
            }

            static public function getName(): string
            {
                return static::$name;
            }

            static public function getIconCode(): string
            {
                return static::$iconCode;
            }

            static public function getHandler(): ?SocServOpenIdHandlerInterface
            {
                return static::$handler;
            }

            static public function setHandler(SocServOpenIdHandlerInterface $handler): void
            {
                static::$handler = $handler;
            }
        };

        $newService::$id = $id;
        $newService::$name = $name;
        $newService::$iconCode = $iconCode;
        $newService::$handler = $handler;
        return $newService;
    }

    static public function selfRegister(EventManager $eventManager): void
    {
        $eventManager->addEventHandler(
            'socialservices',
            'OnAuthServicesBuildList',
            [static::class, 'GetDescription']
        );
    }

    public function __construct(
        $userId = null,
        ?OAuthTransport $transport = null,
        ?LoggerInterface $logger = null
    ) {
        parent::__construct($userId);
        $this->transport = $transport;
        $this->logger = $logger;
    }

    /**
     * @return string[]
     */
    public static function GetDescription(): array
    {
        return [
            "ID" => static::getId(),
            "CLASS" => static::class,
            "NAME" => static::getName(),
            "ICON" => static::getIconCode(),
        ];
    }

    /**
     * @throws ObjectPropertyException
     * @throws SystemException
     * @throws ArgumentException
     */
    public function GetSettings(): array
    {
        $settings = $this->getInternalSettings();
        $keyOptionName = 0;
        foreach ($settings as $i => $option) {
            $optionName = $option[$keyOptionName] ?? '';
            $settings[$i][$keyOptionName] = static::getOptionNameWithPrefix($optionName);
        }
        return $settings;
    }

    /**
     * @throws ObjectPropertyException
     * @throws SystemException
     * @throws ArgumentException
     */
    public function getInternalSettings(): array
    {
        $settings = [
            [static::CONFIG_CLIENT_ID, "Идентификатор клиента", "", ["text", 40]],
            [static::CONFIG_CLIENT_SECRET, "Секрет (пароль) клиента", "", ["text", 40]],
            [static::CONFIG_URL_REDIRECT, "URL для редиректа", "", ["text", 40]],
            [static::CONFIG_SCOPE, "Scope (через пробел)", "openid", ["text", 40]],
            [static::CONFIG_GRANT_TYPE, "Тип авторизации", "openid", [
                "selectbox",
                [OAuthTransport::MODE_CODE_FLOW => 'Code flow', OAuthTransport::MODE_IMPLICIT_FLOW => 'Implicit flow']
            ]],
            [static::CONFIG_USE_USER_INFO_URL, "Использовать URL с информацией о пользователе", "", ["checkbox"]],
            [static::CONFIG_USE_CONFIG_URL, "Использовать URL с настройками OAuth сервиса", "", ["checkbox"]],
        ];

        if (static::needUseOAuthConfigUrl()) {
            $settings = array_merge($settings, [
                [static::CONFIG_URL_CONFIG, "URL с настройками OAuth сервиса", "", ["text", 40]],
                [static::CONFIG_CONFIG_TTL, "TTL кеша настроек", "3600", ["text", 40]]
            ]);
        } else {
            $settings = array_merge($settings, [
                [static::CONFIG_AUTH_URL, "URL для авторизации", "", ["text", 40]],
                [static::CONFIG_TOKEN_URL, "URL для запроса токена доступа", "", ["text", 40]],
                [static::CONFIG_USER_INFO_URL, "URL для запроса информации о пользователе", "", ["text", 40]],
                [static::CONFIG_LOGOUT_URL, "URL для разрыва сессии", "", ["text", 40]],
                [static::CONFIG_SIGNING_ALG, "Алгоритмы для подписи (через пробел)", "HS256 ES256 RS256", ["text", 40]],
                [static::CONFIG_JWKS_URL, "JWKS URL", "", ["text", 40]],
                [static::CONFIG_PUBLIC_KEY, "Публичный ключ", "", ["textarea", 10, 40]],
            ]);
        }

        return array_merge($settings, [
            [static::CONFIG_USER_EXTERNAL_KEY, "Внешний ключ для синхронизации", "sub", ["text", 40]],
            [static::CONFIG_USER_INTERNAL_KEY, "Ключ локального пользователя для синхронизации", "XML_ID", ["text", 40]],
            [static::CONFIG_IGNORE_CASE, "Игнорировать регистр", "", ["checkbox"]],
            [static::CONFIG_USER_NAME_KEY, "Ключ для имени пользователя", "name", ["text", 40]],
            [static::CONFIG_USER_SECOND_NAME_KEY, "Ключ для фамилии пользователя", "second_name", ["text", 40]],
            [static::CONFIG_USER_LAST_NAME_KEY, "Ключ для отчества пользователя", "last_name", ["text", 40]],
            [static::CONFIG_USER_EMAIL_KEY, "Ключ для email пользователя", "email", ["text", 40]],
            [static::CONFIG_ALLOW_CREATE_USER, "Разрешить регистрацию пользователей", "", ["checkbox"]],
            [static::CONFIG_ALLOW_UPDATE_USER, "Разрешить обновление пользователей", "", ["checkbox"]],
            [
                static::CONFIG_USER_GROUPS,
                "Группы для добавления пользователя",
                "email",
                [
                    "multiselectbox",
                    $this->getUserGroupsMap()
                ]
            ],
            [static::CONFIG_USE_LOGGING, "Сохранять логи", "", ["checkbox"]],
            [static::CONFIG_LOG_DIR, "Директория для логов", "", ["text", 40]]
        ]);
    }

    /**
     * @throws ObjectPropertyException
     * @throws SystemException
     * @throws ArgumentException
     */
    private function getUserGroupsMap(): array
    {
        $userGroupMap = [];
        $userGroupQuery = GroupTable::getList([
            'select' => ['ID', 'NAME'],
            'filter' => ['=ACTIVE' => 'Y'],
            'cache' => ['ttl' => 3600]
        ]);

        while ($userGroupData = $userGroupQuery->fetch()) {
            $userGroupMap[$userGroupData['ID']] = $userGroupData['NAME'];
        }

        return $userGroupMap;
    }

    /**
     * @throws LoaderException
     * @throws InvalidArgumentException
     * @throws Throwable
     */
    public function Authorize(): void
    {
        try {
            $this->unsafeAuthorize();
        } catch (Throwable $exception) {
            $handler = static::getHandler();
            if (empty($handler)) {
                throw $exception;
            }

            $handler->handleExceptionAuthorize($exception);
        }
    }

    /**
     * @throws Throwable
     * @throws ArgumentException
     * @throws ObjectPropertyException
     * @throws SystemException
     * @throws InvalidArgumentException
     */
    private function unsafeAuthorize(): void
    {
        $handler = static::getHandler();
        $hasHandler = !empty($handler);
        $code = $hasHandler ? $handler->getAuthorizeCode($this) : $this->getAuthorizeCode();
        if (!empty($code) && !CSocServAuthManager::CheckUniqueKey()) {
            $this->closeWindow('/');
        }

        $idToken = $hasHandler ? $handler->getIdToken($this) : $this->getIdToken();
        $oAuthTransport = $this->getAuthTransport($code, $idToken);
        $externalUserData = $oAuthTransport->getUserData();

        if ($hasHandler) {
            $userId = $handler->saveUserAndGetId($externalUserData, $this);
            $handler->authorizeUser($userId, $this);
        } else {
            $userId = $this->saveUserAndGetId($externalUserData);
            $this->internalAuthorizeUser($userId);
        }

        $this->closeWindow('/');
    }

    /**
     * @throws Exception|Throwable
     */
    private function saveUserDataAndGetUserId(array $updatedUserData): int
    {
        $userId = (int) ($updatedUserData['ID'] ?: 0);
        if (!empty($userId)) {
            $this->updateUser($updatedUserData);
            return $userId;
        }

        return $this->createUser($updatedUserData);
    }

    /**
     * @throws Exception
     */
    private function updateUser(array $updatedUserData): void
    {
        $userId = (int) ($updatedUserData['ID'] ?: 0);
        if ($userId > 0 && $this->allowUpdateUser()) {
            $oUser = new CUser();
            $isSuccess = (bool) $oUser->Update($userId, $updatedUserData);
            if (!$isSuccess) {
                throw new Exception($oUser->LAST_ERROR);
            }

            $this->addUserToGroups($userId);
        }
    }

    /**
     * @throws Exception
     * @throws Throwable
     */
    private function createUser(array $updatedUserData): int
    {
        $userId = (int) ($updatedUserData['ID'] ?: 0);
        if (!empty($userId)) {
            return $userId;
        }

        if(!$this->allowRegisterUser()) {
            throw new Exception('Регистрация пользователей запрещена');
        }

        $oUser = new CUser();
        $updatedUserData['PASSWORD'] = Random::getString(20);
        if (empty($updatedUserData['LOGIN'])) {
            $updatedUserData['LOGIN'] = static::getId() . '_' . Random::getString(10);
        }

        $userId = (int) $oUser->Add($updatedUserData);
        if (empty($userId)) {
            throw new Exception($oUser->LAST_ERROR);
        }

        $this->addUserToGroups($userId);
        return $userId;
    }

    private function addUserToGroups(int $userId): void
    {
        foreach ($this->getUserGroups() as $groupId) {
            try {
                UserGroupTable::add( ['USER_ID' => $userId, 'GROUP_ID' => $groupId]);
            } catch (Throwable $e) {}
        }
    }

    private function closeWindow(string $redirectUrl): void
    {
        global $APPLICATION;
        $APPLICATION->RestartBuffer();?>
        <script type="text/javascript">
            if (window.opener)
                window.opener.location = '<?=CUtil::JSEscape($redirectUrl)?>';
            window.close();
        </script>
        <?php
        die();
    }

    /**
     * @param $arParams
     * @return array|string
     */
    public function GetFormHtml($arParams)
    {
        $url = $this->getUrlForRedirect();
        $phrase = 'OpenId - ' . static::getName();
        return $arParams["FOR_INTRANET"]
            ? ["ON_CLICK" => 'onclick="BX.util.popup(\''.htmlspecialcharsbx(CUtil::JSEscape($url)).'\', 580, 400)"']
            : '<a href="javascript:void(0)" onclick="BX.util.popup(\''.htmlspecialcharsbx(CUtil::JSEscape($url)).'\', 580, 400)" class="bx-ss-button facebook-button"></a><span class="bx-spacer"></span><span>'.$phrase.'</span>';
    }

    /**
     * @param $arParams
     * @return string
     */
    public function GetOnClickJs($arParams): string
    {
        $url = $this->getUrlForRedirect();
        return "BX.util.popup('" . CUtil::JSEscape($url) . "', 460, 420)";
    }

    private function getUrlForRedirect(): string
    {
        try {
            return $this->getAuthTransport()->getUrlForRedirect();
        } catch (Throwable $e) {
            return '';
        }
    }

    /**
     * @throws InvalidArgumentException
     */
    private function getAuthTransport(?string $code = null, ?string $idToken = null): OAuthTransport
    {
        $handler = static::getHandler();
        if (!empty($this->transport)) {
            if (!empty($code)) {
                $this->transport->setCode($code);
            }

            if (!empty($idToken)) {
                $this->transport->setIdToken($idToken);
            }

            if (!empty($handler)) {
                $this->transport->setHandler($handler);
            }
            return $this->transport;
        }

        $parameters = $this->createOAuthParameters();
        $mode = static::isImplicitFlowAuthSchema() ?
            OAuthTransport::MODE_IMPLICIT_FLOW :
            OAuthTransport::MODE_CODE_FLOW;

        $logger = empty($code) ? null : $this->getLogger();
        return new OAuthTransport(
            static::getId(),
            $parameters,
            $code,
            $idToken,
            $mode,
            $handler,
            null,
            $logger
        );
    }

    private function getLogger(): ?LoggerInterface
    {
        if (empty($this->logger) && $this->needLogging()) {
            $logDir = $this->getLogDir() ?? '/upload/logs/auth';
            $this->logger = new SimpleTextLogger(
                Application::getDocumentRoot() . $logDir . '/openid_' . date('Y-m-d').'.log',
                'Y/m/d H:i:s',
                "{date} {level}:\t{message}"
            );
        }
        return $this->logger;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function createOAuthParameters(): OAuthParameters
    {
        $useOAuthConfigUrl = static::needUseOAuthConfigUrl();
        $oAuthConfigUrl = static::getOAuthConfigUrl();
        if ($useOAuthConfigUrl && !empty($oAuthConfigUrl)) {
            $ttl = static::getOAuthConfigTTL();
            return $this->createOAuthParametersByUrl($oAuthConfigUrl, $ttl);
        }

        $parameters = new OAuthParameters();
        static::localClientConfig($parameters);
        $parameters->authUrl = static::getAuthUrl();
        $parameters->tokenUrl = static::getTokenUrl();
        $parameters->userInfoUrl = static::getUserInfoUrl();
        $parameters->logoutUrl = static::getLogoutUrl();
        $parameters->signingAlg = static::getSigningAlg();
        $publicKey = static::getPublicKey();
        $jwkUrl = static::getJwksUrl();
        if (!empty($publicKey)) {
            $parameters->publicKeys = [$publicKey];
        } elseif(!empty($jwkUrl)) {
            $parameters->jwksUrl = $jwkUrl;
            $cache = static::createCache(3600);
            $parameters->loadJwksWithCache($cache);
        }

        return $parameters;
    }

    private static function needUseOAuthConfigUrl(): bool
    {
        return static::GetOption(static::CONFIG_USE_CONFIG_URL) === 'Y';
    }

    private static function getOAuthConfigUrl(): string
    {
        return (string) static::GetOption(static::CONFIG_URL_CONFIG);
    }

    /**
     * @throws InvalidArgumentException
     * @throws ClientExceptionInterface
     */
    private function createOAuthParametersByUrl(string $configUrl, int $ttl): OAuthParameters
    {
        $cache = static::createCache($ttl);
        $handler = static::getHandler();
        $parameters = OAuthParameters::initFromConfigUrlWithCache(
            $configUrl,
            $cache,
            null,
            null,
            null,
            $handler
        );
        static::localClientConfig($parameters);
        return $parameters;
    }

    private static function createCache(int $ttl): CacheInterface
    {
        return new Cache($ttl, null, '/bitrix/cache', '/oauth');
    }

    private static function localClientConfig(OAuthParameters $parameters): void
    {
        $parameters->applicationId = static::getClientId();
        $parameters->applicationSecret = static::getClientSecret();
        $parameters->redirectUrl = static::getRedirectUrl();
        $parameters->scope = static::getScope();
    }


    private static function getClientId(): string
    {
        return (string) static::GetOption(static::CONFIG_CLIENT_ID);
    }

    private static function getClientSecret(): string
    {
        return (string) static::GetOption(static::CONFIG_CLIENT_SECRET);
    }

    private static function getRedirectUrl(): string
    {
        return (string) static::GetOption(static::CONFIG_URL_REDIRECT);
    }

    private static function getScope(): string
    {
        return (string) static::GetOption(static::CONFIG_SCOPE);
    }

    private static function getOAuthConfigTTL(): int
    {
        return (int) static::GetOption(static::CONFIG_CONFIG_TTL);
    }

    private static function getAuthUrl(): string
    {
        return (string) static::GetOption(static::CONFIG_AUTH_URL);
    }

    private static function getTokenUrl(): string
    {
        return (string) static::GetOption(static::CONFIG_TOKEN_URL);
    }

    private static function getUserInfoUrl(): string
    {
        return (string) static::GetOption(static::CONFIG_USER_INFO_URL);
    }

    private static function getLogoutUrl(): string
    {
        return (string) static::GetOption(static::CONFIG_LOGOUT_URL);
    }

    private static function getSigningAlg(): array
    {
        $rawData =  static::GetOption(static::CONFIG_SIGNING_ALG);
        return json_decode($rawData, true) ?: [];
    }

    private static function getPublicKey(): string
    {
        return (string) static::GetOption(static::CONFIG_PUBLIC_KEY);
    }

    private static function getJwksUrl(): string
    {
        return (string) static::GetOption(static::CONFIG_JWKS_URL);
    }

    private function isCodeFlowAuthSchema(): bool
    {
        return static::GetOption(static::CONFIG_GRANT_TYPE) === OAuthTransport::MODE_CODE_FLOW;
    }

    private function isImplicitFlowAuthSchema(): bool
    {
        return static::GetOption(static::CONFIG_GRANT_TYPE) === OAuthTransport::MODE_IMPLICIT_FLOW;
    }

    public function getAuthorizeCode(?HttpRequest $request = null): ?string
    {
        $request = $request ?? Context::getCurrent()->getRequest();
        $code = $request->get('code') ?: null;
        return $code === null ? null : (string) $code;
    }

    public function getIdToken(?HttpRequest $request = null): ?string
    {
        $request = $request ?? Context::getCurrent()->getRequest();
        $idToken = $request->get('id_token') ?: null;
        return $idToken === null ? null : (string) $idToken;
    }


    /**
     * @throws Throwable
     * @throws ArgumentException
     * @throws ObjectPropertyException
     * @throws SystemException
     */
    public function saveUserAndGetId(array $externalUserData): string
    {
        $updatedUserData = $this->getUpdatedUserByExternalData($externalUserData);
        return $this->saveUserDataAndGetUserId($updatedUserData);
    }

    public function internalAuthorizeUser(string $userId): void
    {
        global $USER;
        $USER->Authorize($userId, true, true);
    }

    /**
     * @throws ObjectPropertyException
     * @throws SystemException
     * @throws ArgumentException
     */
    private function getUpdatedUserByExternalData(array $externalUserData): array
    {
        $userData = $this->getLocalUserDataByExternalUserData($externalUserData);
        $userData['ACTIVE'] = 'Y';

        $userName = $externalUserData[$this->getUserNameKey() ?: 'null'] ?? null;
        if ($userName !== null) {
            $userData['NAME'] = $userName;
        }

        $userLastName = $externalUserData[$this->getUserLastNameKey() ?: 'null'] ?? null;
        if ($userLastName !== null) {
            $userData['LAST_NAME'] = $userLastName;
        }

        $userSecondName = $externalUserData[$this->getUserSecondNameKey() ?: 'null'] ?? null;
        if ($userSecondName !== null) {
            $userData['SECOND_NAME'] = $userSecondName;
        }

        $userEmail = $externalUserData[$this->getUserEmailKey() ?: 'null'] ?? null;
        if ($userEmail !== null) {
            $userData['EMAIL'] = $userEmail;
        }

        $externalUserId = $externalUserData[$this->getUserExternalKey() ?: 'null'] ?? null;
        if ($externalUserId !== null) {
            $internalKey = $this->getInternalKey();
            $userData[$internalKey] = $externalUserId;
        }

        return $userData;
    }

    /**
     * @throws ObjectPropertyException
     * @throws SystemException
     * @throws ArgumentException
     * @throws Exception
     */
    private function getLocalUserDataByExternalUserData(array $externalUserData): array
    {
        $externalKey = $this->getUserExternalKey();
        $internalKey = $this->getInternalKey();
        $externalId = $externalUserData[$externalKey] ?? null;
        if (empty($externalId)) {
            return [];
        }

        $allowRegistration = $this->isAllowedRegisterNewUser();
        try {
            $params = [
                'select' => ['ID', 'NAME', 'LAST_NAME', 'SECOND_NAME', 'EMAIL', 'LOGIN', 'ACTIVE'],
                'filter' => ['=' . $internalKey => $externalId],
                'limit' => 1
            ];

            if ($this->neeIgnoreCase()) {
                $params['runtime'][] = new ExpressionField('INTERNAL_KEY', 'UPPER(%s)', [$internalKey]);
                $params['filter'] = ['=INTERNAL_KEY' => strtoupper((string)$externalId)];
            }

            return UserTable::getList($params)->fetch() ?: [];
        } catch (Exception $e) {
            if ($allowRegistration) {
                throw new Exception('Пользователь не найден: ' . $e->getMessage());
            }
            return [];
        }
    }

    private function getUserExternalKey(): string
    {
        return (string) static::GetOption(static::CONFIG_USER_EXTERNAL_KEY);
    }

    private function getInternalKey(): string
    {
        return (string) static::GetOption(static::CONFIG_USER_INTERNAL_KEY);
    }

    private function neeIgnoreCase(): bool
    {
        return static::GetOption(static::CONFIG_IGNORE_CASE) === 'Y';
    }

    private function getUserNameKey(): string
    {
        return (string) static::GetOption(static::CONFIG_USER_NAME_KEY);
    }

    private function getUserSecondNameKey(): string
    {
        return (string) static::GetOption(static::CONFIG_USER_SECOND_NAME_KEY);
    }

    private function getUserLastNameKey(): string
    {
        return (string) static::GetOption(static::CONFIG_USER_LAST_NAME_KEY);
    }

    private function getUserEmailKey(): string
    {
        return (string) static::GetOption(static::CONFIG_USER_EMAIL_KEY);
    }

    private function allowRegisterUser(): bool
    {
        return static::GetOption(static::CONFIG_ALLOW_CREATE_USER) === 'Y';
    }

    private function allowUpdateUser(): bool
    {
        return static::GetOption(static::CONFIG_ALLOW_UPDATE_USER) === 'Y';
    }

    private function getUserGroups(): array
    {
        $rawGroups = static::GetOption(static::CONFIG_USER_GROUPS);
        return explode(',', $rawGroups) ?: [];
    }

    private function needLogging(): bool
    {
        return static::GetOption(static::CONFIG_USE_LOGGING) === 'Y';
    }

    private function getLogDir(): string
    {
        return static::GetOption(static::CONFIG_LOG_DIR) ?: '';
    }

    public static function OptionsSuffix(): string
    {
        return parent::OptionsSuffix() . '_' . md5(static::class);
    }

    public static function GetOption($opt)
    {
        return parent::GetOption(static::getOptionNameWithPrefix($opt));
    }

    static private function getOptionNameWithPrefix(string $optionName): string
    {
        return static::getId() . '_' . $optionName;
    }
}
