<?php

IncludeModuleLangFile(__FILE__);
use \Bitrix\Main\ModuleManager;

class bx_openid extends CModule
{
    public $MODULE_ID = "bx.openid";
    public $MODULE_VERSION;
    public $MODULE_VERSION_DATE;
    public $MODULE_NAME;
    public $MODULE_DESCRIPTION;
    public $errors;

    public function __construct()
    {
        $this->MODULE_VERSION = "1.0.0";
        $this->MODULE_VERSION_DATE = "2024-06-07 07:20:54";
        $this->MODULE_NAME = "Название модуля";
        $this->MODULE_DESCRIPTION = "Описание модуля";
    }

    public function DoInstall(): bool
    {
        $this->InstallFiles();
        ModuleManager::RegisterModule($this->MODULE_ID);
        return true;
    }

    public function DoUninstall(): bool
    {
        $this->UnInstallFiles();
        ModuleManager::UnRegisterModule($this->MODULE_ID);
        return true;
    }

    public function InstallFiles()
    {
        CopyDirFiles(__DIR__ . "/files", $_SERVER["DOCUMENT_ROOT"], true, true);
        return true;
    }

    public function UnInstallFiles()
    {
        DeleteDirFiles(__DIR__ . "/files", $_SERVER["DOCUMENT_ROOT"]);
        return true;
    }
}
