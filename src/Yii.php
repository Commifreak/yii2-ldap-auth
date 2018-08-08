<?php
/**
 * Yii bootstrap file.
 * Used for enhanced IDE code autocompletion.
 */
class Yii extends \yii\BaseYii
{
    /**
     * @var BaseApplication|WebApplication|ConsoleApplication the application instance
     */
    public static $app;
}

/**
 * Class WebApplication
 * Include only Web application related components here
 *
 * @property \vendor\commifreak\yii2-ldap-auth\LdapAuth $ldap
 */
class WebApplication extends yii\web\Application
{
}

