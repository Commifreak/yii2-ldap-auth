<?php
/**
 * Created by PhpStorm.
 * User: Robin
 * Date: 07.08.2018
 * Time: 11:21
 */

namespace commifreak\yii2;

use Yii;
use yii\base\ErrorException;
use yii\base\Exception;
use yii\helpers\IpHelper;

class LdapAuth
{

    /**
     * Defines the doamins to use.
     * @var array
     */
    public $domains = [
        [
            'name' => 'Example',
            'useSSL' => false,
            'hostname' => 'example.tld',
            'autodetectIps' => ['172.31.0.0/16', '192.168.178.0/24', '127.0.0.1'],
            'baseDn' => 'DC=Example,DC=tld',
            'publicSearchUser' => 'example@domain',
            'publicSearchUserPassword' => 'secret',
        ],
    ];

    /**
     * If false (default) any user search would return the whole result.
     * If true, the script checks every users sidHistory and only return results which are newer (migrated).
     * A use case for `true`: You have two domains and user "Foo" was copied from Domain 1 to Domain 2 without deleting it from Domain 1 - now you have 2 results for a search "Foo", but the entry in Domain 2 has a set "sidHistory" with its sid from Domain 1.
     * Setting this tp true will filter out the "Foo" from Domain 1, since its sid is listed in the Domain 2 entry of it.
     *
     * @see https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory
     * @see https://ldapwiki.com/wiki/SIDHistory
     * @var bool
     */
    public $filterBySidhistory = false;

    private $_ldapBaseDn;
    private $_l;
    private $_username;


    public function __construct()
    {

        if (!function_exists('ldap_connect')) {
            throw new Exception("LDAP-extension missing :(");
        }

    }

    // Thanks to: https://www.php.net/manual/de/function.ldap-connect.php#115662
    private function serviceping($host, $port = 389, $timeout = 5)
    {
        if ($port === null) {
            $port = 389;
        }

        Yii::debug('Host: ' . $host . ' Port: ' . $port, __METHOD__);

        try {
            $op = fsockopen($host, $port, $errno, $errstr, $timeout);
        } catch (ErrorException $e) {
            Yii::error('fsockopen failure!', __METHOD__);
            return false;
        }
        if (!$op) return false; //DC is N/A
        else {
            fclose($op); //explicitly close open socket connection
            return true; //DC is up & running, we can safely connect with ldap_connect
        }
    }


    /**
     * @param boolean $overrideIp If you want, you can pass a IP address instead using the autodetected one
     * @return false|int
     */
    public function autoDetect($overrideIp = false)
    {

        if (count($this->domains) <= 1) {
            return 0;
        }

        $clientIp = $overrideIp ? $overrideIp : (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null));

        if (empty($clientIp)) {
            Yii::debug('[Autodetect] No client ip detected, skipping auto detection', __METHOD__);
            return 0;
        }

        $index = 0;
        foreach ($this->domains as $config) {
            Yii::debug('[Autodetect] Processing ' . $config['name'], __METHOD__);
            if (!isset($config['autodetectIps']) || empty($config['autodetectIps'])) {
                Yii::debug('[Autodetect] No Ips for ' . $config['name'], __METHOD__);
                continue;
            }
            foreach ($config['autodetectIps'] as $ip) {
                if (IpHelper::inRange($clientIp, $ip)) {
                    Yii::debug('[Autodetect] Domain found!', __METHOD__);
                    return $index;
                }
            }
            $index++;
        }

        Yii::warning('[Autodetect] No suitable domain found :(', __METHOD__);
        return false;
    }


    /**
     * @param string $username The username to use
     * @param string $password The users AD/LDAP password
     * @param integer $domainKey The array key of the domain config to use
     * @param boolean $fetchUserDN If true, determine users DN and use that as username
     * @throws ErrorException
     */
    public function login($username, $password, $domainKey, $fetchUserDN = false)
    {

        Yii::debug('Hello! :) Trying to log you in via LDAP!', __METHOD__);


        $domainData = $this->domains[$domainKey];

        $ssl = isset($domainData['useSSL']) && $domainData['useSSL'];
        Yii::debug('Use SSL here? ' . ($ssl ? 'Yes' : 'No'), __METHOD__);

        if ($ssl) {
            // When using SSL, we have to set some env variables and create an ldap controlfile - otherwirse a connect with non valid certificat will fail!

            /**
             * Inhalt der .ldaprc:
             * TLS_REQCERT allow
             *
             */
            if (isset($_SERVER['HOME']) && strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
                $ldaprcfile = $_SERVER['HOME'] . '/.ldaprc';

                if (!file_exists($ldaprcfile)) {
                    // Try to create the file
                    if (!@file_put_contents($ldaprcfile, 'TLS_REQCERT allow')) {
                        Yii::error('Cannot create required .ldaprc control file!', __METHOD__);
                        return false;
                    }
                } else {
                    Yii::debug('.ldaprc file exists!', __METHOD__);
                }
                putenv('LDAPCONF=' . $ldaprcfile);
            } else {
                Yii::debug("Not a windows environment!", __METHOD__);
            }

            putenv('LDAPTLS_REQCERT=allow');
            putenv('TLS_REQCERT=allow');
        }

        Yii::debug('Trying to connect to Domain #' . $domainKey . ' (' . $domainData['hostname'] . ')', __METHOD__);

        if (!self::serviceping($domainData['hostname'], $ssl ? 636 : null)) {
            Yii::error('Connection failed!', __METHOD__);
            return false;
        }

        $hostPrefix = ($ssl ? 'ldaps://' : 'ldap://') . $domainData['hostname'];
        $port = $ssl ? 636 : 389;

        Yii::debug('Connecting to ' . $hostPrefix . ', Port: ' . $port, __METHOD__);

        $l = @ldap_connect($hostPrefix, $port);
        if (!$l) {
            Yii::warning('Connect failed! ' . ldap_error($l), __METHOD__);
            return false;
        }

        ldap_set_option($l, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($l, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($l, LDAP_OPT_NETWORK_TIMEOUT, 3);

        if ($fetchUserDN) {
            Yii::debug("We have to determine the user DN first!", __METHOD__);
            $userDNSearch = $this->searchUser($username, ['dn'], null, $domainKey);
            Yii::debug("fetchUserDN: yes - Result:", __METHOD__);
            Yii::debug($userDNSearch, __METHOD__);

            $firstArrayKey = !$userDNSearch ? false : array_key_first($userDNSearch);

            if ($userDNSearch && count($userDNSearch) == 1 && $firstArrayKey) {
                Yii::debug("Overwrite username " . $username . " to " . $userDNSearch[$firstArrayKey]['dn'], __METHOD__);
                $username = $userDNSearch[$firstArrayKey]['dn'];
            } else {
                Yii::warning("Should overwrite username to DN, but something went wrong while finding the users DN. Leave it as is", __METHOD__);
            }
        }

        $bind_dn = strpos($username, '@') === false && strpos($username, ',') === false ? $username . '@' . $domainData['name'] : $username;

        Yii::debug('Trying to authenticate with DN ' . $bind_dn, __METHOD__);

        $b = @ldap_bind($l, $bind_dn, $password);

        if (!$b) {
            Yii::warning('Bind failed! ' . ldap_error($l), __METHOD__);
            return false;
        }

        $this->_l          = $l;
        $this->_ldapBaseDn = $domainData['baseDn'];
        $this->_username   = $username;

        return true;


    }

    /**
     * @param array $attributes AD/LDAP attributes to return
     * @return array|false
     */
    public function fetchUserData($attributes = "")
    {
        if (empty($attributes)) {
            $attributes = ['sn', 'objectSid', 'sIDHistory', 'givenName', 'mail', 'telephoneNumber'];
        }

        array_push($attributes, 'objectSid'); # Push objectsid, regardless of source array, as we need it ALWAYS!
        array_push($attributes, 'sIDHistory'); # Push sIDHistory, regardless of source array, as we need it ALWAYS!

        $search_filter = '(&(objectCategory=person)(samaccountname=' . $this->_username . '))';

        $result = ldap_search($this->_l, $this->_ldapBaseDn, $search_filter, $attributes);

        if ($result) {
            $entries = ldap_get_entries($this->_l, $result);
            if ($entries['count'] > 1 || $entries['count'] == 0) {
                return false;
            }
            if (!isset($entries[0]) && !isset($entries[0]['objectsid'])) {
                Yii::error('No objectsid!', __METHOD__);
                return false;
            }
            $sid        = self::SIDtoString($entries[0]['objectsid'])[0];
            $sidHistory = isset($entries[0]['sidhistory']) ? self::SIDtoString($entries[0]['sidhistory']) : null;
            return array_merge(['sid' => $sid, 'sidhistory' => $sidHistory], self::handleEntry($entries[0]));
        } else {
            return false;
        }
    }

    /**
     * @param string $searchFor Search-Term
     * @param array|null $attributes Attributes to get back
     * @param string|null $searchFilter Filter string
     * @param boolean $autodetect Use autodetect to detect domain? You can also provide integer domainkey, this is then used as target domain!
     * @return array|bool
     */
    public function searchUser($searchFor, $attributes = "", $searchFilter = "", $autodetect = true)
    {

        if (empty($searchFor) && empty($searchFilter)) {
            Yii::error("Search input and custom searchFilter are empty!", __METHOD__);
            return false;
        }

        if (empty($attributes)) {
            $attributes = ['sn', 'objectSid', 'sIDHistory', 'givenName', 'mail', 'telephoneNumber', 'l', 'physicalDeliveryOfficeName'];
        }

        array_push($attributes, 'objectSid'); # Push objectsid, regardless of source array, as we need it ALWAYS!
        array_push($attributes, 'sIDHistory'); # Push sIDHistory, regardless of source array, as we need it ALWAYS!

        if (empty($searchFilter)) {
            $searchFilter = "(&(objectCategory=person)(|(objectSid=%searchFor%)(sIDHistory=%searchFor%)(samaccountname=*%searchFor%*)(mail=*%searchFor%*)(sn=*%searchFor%*)(givenName=*%searchFor%*)(l=%searchFor%)(physicalDeliveryOfficeName=%searchFor%)))";
        }

        if (is_bool($autodetect)) {
            if ($autodetect) {
                Yii::debug("Domain auto detection used", __METHOD__);
                $autoDomain = $this->autoDetect();
            } else {
                Yii::debug("Domain autodetect disabled, searching in ALL domains!", __METHOD__);
                $autoDomain = false;
            }


            if ($autodetect && $autoDomain === false) {
                Yii::warning("Autodetect enabled but detection was not successful!", __METHOD__);
                return false;
            }

            $domains = $autodetect ? [$this->domains[$autoDomain]] : $this->domains;
            $i       = $autodetect ? $autoDomain : 0;
        } else {
            Yii::debug("Static domainkey provided: " . $autodetect, __METHOD__);
            if (!array_key_exists($autodetect, $this->domains)) {
                throw new ErrorException("Provided domainKey does not exist!");
            }
            $domains = [$this->domains[$autodetect]];
            $i       = $autodetect;
        }

        $return = [];
        foreach ($domains as $domain) {
            Yii::debug($domain, __METHOD__);
            if (!$this->login($domain['publicSearchUser'], $domain['publicSearchUserPassword'], $i)) {
                if (empty($this->_l)) {
                    throw new ErrorException('LDAP Connect or Bind error on ' . $domain['hostname']);
                } else {
                    throw new ErrorException('LDAP Connect or Bind error (' . ldap_errno($this->_l) . ' - ' . ldap_error($this->_l) . ') on ' . $domain['hostname']);
                }
            }

            $searchFilter = str_replace("%searchFor%", addslashes($searchFor), $searchFilter);

            Yii::debug('Search-Filter: ' . $searchFilter, __METHOD__);

            $result = ldap_search($this->_l, $this->_ldapBaseDn, $searchFilter, $attributes);

            if ($result) {
                $entries = ldap_get_entries($this->_l, $result);
                foreach ($entries as $entry) {
                    if (!is_array($entry) || empty($entry)) {
                        continue;
                    }
                    if (!isset($entry['objectsid'])) {
                        Yii::warning('No objectsid! ignoring!', __METHOD__);
                        continue;
                    }
                    $sid = self::SIDtoString($entry['objectsid'])[0];
                    $sidHistory = isset($entry['sidhistory']) ? self::SIDtoString($entry['sidhistory']) : null;


                    if ($this->filterBySidhistory) {
                        // Check if this user is maybe already listed in the results - ifo so, determine which one is newer
                        foreach ($return as $_sid => $_data) {
                            if (!empty($_data['sidhistory']) && in_array($sid, $_data['sidhistory'])) {
                                Yii::debug('This user is listed in another users history - skipping', __METHOD__);
                                continue 2;
                            }
                        }

                        if ($sidHistory) {
                            foreach ($sidHistory as $item) {
                                if (array_key_exists($item, $return)) {
                                    Yii::debug('User already exists with its sidhistory in results! Unsetting the old entry...', __METHOD__);
                                    unset($return[$item]);
                                }
                            }
                        }
                    }


                    $additionalData = ['sid' => $sid, 'sidhistory' => $sidHistory, 'dn' => $entry['dn'], 'domainKey' => $i];
                    if (count($this->domains) > 1) {
                        // Enable domainName output if more than one domains configured
                        $additionalData['domainName'] = $this->domains[$i]['name'];
                    }
                    $return[$sid] = array_merge($additionalData, self::handleEntry($entry));
                }
            }
            $i++;

            // Reset LDAP Link
            ldap_close($this->_l);
            $this->_l = null;
        }

        Yii::debug("Result:", __METHOD__);
        Yii::debug($return, __METHOD__);

        return empty($return) ? [] : $return;


    }

    public static function SIDtoString($ADsid)
    {
        $results = [];
        Yii::debug('Converting SID...', __METHOD__);
        for ($cnt = 0; $cnt < $ADsid['count']; $cnt++) {
            Yii::debug('Run ' . $cnt, __METHOD__);
            $sid = "S-";
            //$ADguid = $info[0]['objectguid'][0];
            $sidinhex = str_split(bin2hex($ADsid[$cnt]), 2);
            // Byte 0 = Revision Level
            $sid = $sid . hexdec($sidinhex[0]) . "-";
            // Byte 1-7 = 48 Bit Authority
            $sid = $sid . hexdec($sidinhex[6] . $sidinhex[5] . $sidinhex[4] . $sidinhex[3] . $sidinhex[2] . $sidinhex[1]);
            // Byte 8 count of sub authorities - Get number of sub-authorities
            $subauths = hexdec($sidinhex[7]);
            //Loop through Sub Authorities
            for ($i = 0; $i < $subauths; $i++) {
                $start = 8 + (4 * $i);
                // X amount of 32Bit (4 Byte) Sub Authorities
                $sid = $sid . "-" . hexdec($sidinhex[$start + 3] . $sidinhex[$start + 2] . $sidinhex[$start + 1] . $sidinhex[$start]);
            }
            Yii::debug('Converted SID to: ' . $sid, __METHOD__);
            array_push($results, $sid);
        }
        return $results;
    }

    public static function handleEntry($entry)
    {
        $newEntry = [];
        foreach ($entry as $attr => $value) {
            if (is_int($attr) || $attr == 'objectsid' || $attr == 'sidhistory' || !isset($value['count'])) {
                continue;
            }
            $count = $value['count'];
            $newVal = "";
            for ($i = 0; $i < $count; $i++) {
                $newVal .= $value[$i];
            }
            $newEntry[$attr] = $newVal;
        }
        return $newEntry;
    }

}