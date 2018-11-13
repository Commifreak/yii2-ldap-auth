# yii2-ldap-auth

This extensions adds a simple LDAP-Auth mechanism for your yii2 application

## What it does

* Tries to bind to selected domain with username/credential entered in LoginForm
* Read user data attributes after successful bind to retrieve sid and other values

## Features

* User login via LDAP
* Read self defined LDAP attributes
* Domain autodetection based on IPFilter.

## Installation

Preferred way to install, is through composer:

```
composer require commifreal/yii2-ldap-auth
```

## Setup

Either you use it as standalone or add this as component:

```php
...
[
   'components' => [
      ...
      'ldap' => [
            'class' => 'commifreak\yii2\LdapAuth',
            'domains' => [
                ['name' => 'Domain1', 'hostname' => 'domain1.tld', 'autodetectIps' => ['172.31.0.0/16', '192.168.178.0/24', '127.0.0.1'], 'baseDn' => 'DC=Domain1,DC=tld', 'publicSearchUser' => 'example@domain', 'publicSearchUserPassword' => 'secret'],
                ['name' => 'Domain2', 'hostname' => '192.168.178.14', 'autodetectIps' => ['192.168.178.55'], 'baseDn' => 'DC=Domain2,DC=tld', 'publicSearchUser' => 'example@domain', 'publicSearchUserPassword' => 'secret'],
                ...
            ],
        ],
        ...
     ]
```

You can omit `autodetectIps` if you dont want Ips for a specific domain.

__Attention!__ You need to define `baseDn`. This defines the baseDN in where the function will search for the user data!

## Usage

There are 3 basic functions:

* `autoDetect()`
  * Tries to detect the User's client IP (with Proxy support) and determines the Domain to use
* `login($username, $password, $domainKey)`
  * Tries to connect to domain and bind to it as `$username` with `$password`
* `fetchUserData($attributes)`
  * Queries the LDAP for the logged in user and gets some attributes (adjustable list of attributes)
* `searchUser($searchFor, $attributes, $searchFilter)`
  * Searches for a user in the LDAP-Directory. This requires a search-user which is configured in the component options.
  * The options let you define what attributes you want back and in which you are searching (defaults to lastname, firstname, username and class=person).

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

To use the *autoDetect* feature, you have to fill `location` before, like:

```php
class LoginForm extends Model
{

    ...

    public function init()
    {
        parent::init(); // TODO: Change the autogenerated stub
        $this->location = Yii::$app->ldap->autoDetect();

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


        if (Yii::$app->ldap->login($this->username, $this->password, $this->location)) {
            $userData = Yii::$app->ldap->fetchUserData();
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

## The database

I've added/changed the user table as follow, to add a sid, firstname, lastname and phone column:

```sql
CREATE TABLE `user` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `sid` varchar(255) DEFAULT NULL,
  `email` varchar(256) NOT NULL,
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
