# yii2-ldap-auth

This extensions adds a simple LDAP-Auth mechanism for your yii2 application

## What it does

* Tries to bind to selected domain with username/credential entered in LoginForm
* Read user data attributes after successful bind to retrieve sid and other values

## Features

* User login via LDAP
* Read self defined LDAP attributes
* Domain autodetection based on IPFilter.
* Filter out results by checking every results `sidHistory`
* Optional query caching

## Installation

Preferred way to install, is through composer:

```
composer require commifreak/yii2-ldap-auth
```

## Setup

Either you use it as standalone or add this as component:

```php
[
   'components' => [
      'ldap' => [
            'class' => 'commifreak\yii2\LdapAuth',
            'filterBySidhistory' => false, // Filter by checking sidHistory?
            'enableCache' => false,
            'forceApcuCache' => false,
            'apcuCacheTtl' => 3600,
            'domains' => [
                ['name' => 'Domain1', 'hostname' => 'domain1.tld', 'autodetectIps' => ['172.31.0.0/16', '192.168.178.0/24', '127.0.0.1'], 'baseDn' => 'DC=Domain1,DC=tld', 'publicSearchUser' => 'example@domain', 'publicSearchUserPassword' => 'secret'],
                ['name' => 'Domain2', 'hostname' => '192.168.178.14', 'autodetectIps' => ['192.168.178.55'], 'baseDn' => 'DC=Domain2,DC=tld', 'publicSearchUser' => 'example@domain', 'publicSearchUserPassword' => 'secret'],
                //...
            ],
        ],
     ]
]
```

You can omit `autodetectIps` if you don't want Ips for a specific domain.

You can set `useSSL` if you want to use encryption.

__Attention!__ You need to define `baseDn`. This defines the baseDN in where the function will search for the user data!

## Usage

There are 5 basic functions:

* `autoDetect($overrideIp)`
  * Tries to detect the User's client IP (with Proxy support) and determines the Domain to use
* `login($username, $password, $domainKey, $fetchUserDN)`
  * Tries to connect to domain and bind to it as `$username` with `$password`
  * `$domainKey` defines the domain to use (either detected by `autoDetect` or by passing the key number of the
    configuration array)
    * If you set it to `false` or pass nothing, the login function loops through every domain and tries to log you in (
      default).
  * `$fetchUserDN` determines the user DN, in case you want a bind via a users DN instead of username@hostname
* `fetchUserData($attributes)`
  * Queries the LDAP for the logged in user and gets some attributes (adjustable list of attributes)
* `searchUser($searchFor, $attributes, $searchFilter, $domainKey, $onlyActiveAccounts, $allDomainsHaveToBeReachable)`
  * Searches for a user in the LDAP-Directory. This requires a search-user which is configured in the component options.
  * The options let you define what attributes you want back and in which you are searching (defaults to lastname,
    firstname, username and class=person).
  * `$domainKey` lets you set a fixed domain (from autoDetect as example) to search. Otherwise, it searches in every
    domain
  * `$onlyActiveAccounts` lets you decide whether you only want active or all accounts to be returned. defaults to
    false!
  * `$allDomainsHaveToBeReachable` True: All configured domains need to be reachable in order to get a result. If one is
    not reachable, false will be returned
* `updateAttributes` lets you update the user attributes
  * `$attributes` The attribute (array keys are the attribute names, the array values are the attribute values)
  * `$dn` The DN which should be updated - if not provided, the eventually previous examined one will be used.

## Example

### View

I've added a new attribute to LoginForm `location` which holds the domain-key.

```php
<?= $form->field($model, 'location')->widget(\kartik\select2\Select2::className(), [
        'data' => \yii\helpers\ArrayHelper::getColumn(Yii::$app->ldap->domains, 'name'),
        'options' => ['placeholder' => 'Select a domain ...'],
        'pluginOptions' => [
            'allowClear' => true
        ],
    ]) ?>
```

To use the *autoDetect* feature, you have now nothing else to do! The plugin takes care of it automatically! You just
want to set the location dropdown to 0, by setting the following inside your LoginForm:

```php
    public function init()
    {
        parent::init(); // TODO: Change the autogenerated stub
        $this->location = 0; // Set it to the first entry, which is now always autodetected
    }
```

### Login

This is based on the default LoginForm->login() function

```php
public function login()
    {
        if (!$this->validate()) {
            return false;
        }

        // At this point we filled the model - now we ask the LDAP if the entered data is correct
        
        /** @var LdapAuth $ldap */
        $ldap = Yii::$app->ldap;


        if ($ldap->login($this->username, $this->password, $this->location)) { // or if ($ldap->login($this->username, $this->password, $this->location, true)) if you want to use `$fetchUserDN`-feature!
            $userData = $ldap->fetchUserData();
            if ($userData) {
                $user = User::find()->where(['sid' => $userData['sid']])->one();

                if (!$user) {
                    $user = new User();
                    $user->sid = $userData['sid'];
                }

                $user->email = $userData['mail'];
                $user->firstname = $userData['givenname'];
                $user->lastname = $userData['sn'];
                $user->phone = $userData['telephonenumber'];

                $user->validate();
                $user->save();

                return Yii::$app->user->login($user, $this->rememberMe ? 3600 * 24 * 30 : 0);
            }
        } else {
            Yii::$app->session->setFlash('error', 'Login gescheitert!');
        }
    }
```

This also tries to sync user's data with the LDAP.

### User attribute update

```php
/** @var LdapAuth $ldap */
$ldap = \Yii::$app->ldap;

if (!$ldap->login(\Yii::$app->user->identity->sid, $this->userPassword, false, true)) {
    return false;
}

$updateAttrs = [];

if (!empty($this->phone)) {
    $updateAttrs['telephonenumber'] = $this->phone;
}

if (!empty($this->room)) {
    $updateAttrs['physicaldeliveryofficename'] = $this->room;
}

if (!$ldap->updateAttributes($updateAttrs)) {
    return false;
}
```

## The database

I've added/changed the user table as follow, to add a sid, firstname, lastname and phone column:

```sql
CREATE TABLE `user`
(
  `id`             int(10) unsigned NOT NULL AUTO_INCREMENT,
  `sid`            varchar(255) DEFAULT NULL,
  `email`          varchar(256) NOT NULL,
  `firstname` varchar(255) DEFAULT NULL,
  `lastname` varchar(255) DEFAULT NULL,
  `phone` varchar(255) DEFAULT NULL,
  `create_time` datetime DEFAULT NULL,
  `create_user` int(11) DEFAULT NULL,
  `update_time` datetime DEFAULT NULL,
  `update_user_id` int(11) DEFAULT NULL,
  `auth_key` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_key_UNIQUE` (`auth_key`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8;

```
