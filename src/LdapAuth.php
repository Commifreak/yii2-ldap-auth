<?php
/**
 * Created by PhpStorm.
 * User: Robin
 * Date: 07.08.2018
 * Time: 11:21
 */

namespace commifreak\yii2;

use Yii;
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
            'hostname' => 'example.tld',
            'autodetectIps' => ['172.31.0.0/16', '192.168.178.0/24', '127.0.0.1'],
            'baseDn' => 'DC=Example,DC=tld',
            'publicSearchUser' => 'example@domain',
            'publicSearchUserPassword' => 'secret',
        ],
    ];

    private $_ldapBaseDn;
    private $_l;
    private $_username;


    public function __construct()
    {

        if (!function_exists('ldap_connect')) {
            throw new Exception("LDAP-extension missing :(");
        }

    }


    public function autoDetect($overrideIp = false)
    {

        if (count($this->domains) <= 1) {
            return 0;
        }

        $clientIp = $overrideIp ? $overrideIp : (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR']);

        foreach ($this->domains as $config) {
            Yii::debug('Processing ' . $config['name']);
            if (!isset($config['autodetectIps']) || empty($config['autodetectIps'])) {
                Yii::debug('No Ips for ' . $config['name']);
                continue;
            }
            foreach ($config['autodetectIps'] as $ip) {
                if (IpHelper::inRange($clientIp, $ip)) {
                    Yii::debug('Domain found!');
                    $useDomain = $config['name'];
                    break;
                }
            }
            if (isset($useDomain)) {
                break;
            }
        }

        if (isset($useDomain)) {
            return array_search($useDomain, array_keys($this->domains));
        } else {
            return false;
        }
    }


    public function login($username, $password, $domainKey)
    {


        $domainData = $this->domains[$domainKey];

        Yii::debug('Trying to connect to Domain #' . $domainKey . ' (' . $domainData['hostname'] . ')');

        $l = @ldap_connect($domainData['hostname']);
        if (!$l) {
            Yii::debug('Login failed!', 'ldapAuth');
            return false;
        }

        ldap_set_option($l, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($l, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($l, LDAP_OPT_NETWORK_TIMEOUT, 3);

        $b = @ldap_bind($l, strpos($username, '@') === false ? $username . '@' . $domainData['name'] : $username, $password);

        if (!$b) {
            Yii::debug('Bind failed!', 'ldapAuth');
            return false;
        }

        $this->_l = $l;
        $this->_ldapBaseDn = $domainData['baseDn'];
        $this->_username = $username;

        return true;


    }

    public function fetchUserData($attributes = "")
    {
        if (empty($attributes)) {
            $attributes = ['sn', 'objectSid', 'givenName', 'mail', 'telephoneNumber'];
        }

        array_push($attributes, 'objectSid'); # Push objectsid, regardless of source array, as we need it ALWAYS!

        $search_filter = '(&(objectCategory=person)(samaccountname=' . $this->_username . '))';

        $result = ldap_search($this->_l, $this->_ldapBaseDn, $search_filter, $attributes);

        if ($result) {
            $entries = ldap_get_entries($this->_l, $result);
            if ($entries['count'] > 1) {
                return false;
            }
            $sid = self::SIDtoString($entries[0]['objectsid'][0]);
            return array_merge(['sid' => $sid], self::handleEntry($entries[0]));
        } else {
            return false;
        }
    }

    /**
     * @param $searchFor Search-Term
     * @param array $attributes Attributes to get back
     * @param string $searchFilter Filter string
     * @param bool $autodetect Use autodetect to detect domain?
     * @return array|bool
     */
    public function searchUser($searchFor, $attributes = "", $searchFilter = "", $autodetect = true)
    {

        if (empty($searchFor)) {
            return false;
        }

        if (empty($attributes)) {
            $attributes = ['sn', 'objectSid', 'givenName', 'mail', 'telephoneNumber', 'l', 'physicalDeliveryOfficeName'];
        }

        array_push($attributes, 'objectSid'); # Push objectsid, regardless of source array, as we need it ALWAYS!

        if (empty($searchFilter)) {
            $searchFilter = "(&(objectCategory=person)(|(objectSid=%searchFor%)(samaccountname=*%searchFor%*)(mail=*%searchFor%*)(sn=*%searchFor%*)(givenName=*%searchFor%*)(l=%searchFor%)(physicalDeliveryOfficeName=%searchFor%)))";
        }

        if ($autodetect) {
            $autoDomain = $this->autoDetect();
        } else {
            $autoDomain = false;
        }


        if ($autodetect && $autoDomain === false) {
            return false;
        }

        $domains = $autodetect ? [$this->domains[$autoDomain]] : $this->domains;

        $return = [];
        $i = 0;
        foreach ($domains as $domain) {
            Yii::debug($domain, 'ldapAuth');
            if (!$this->login($domain['publicSearchUser'], $domain['publicSearchUserPassword'], $i)) {
                Yii::error('LDAP Login error!');
                continue;
            }

            $searchFilter = str_replace("%searchFor%", addslashes($searchFor), $searchFilter);

            Yii::debug('Search-Filter: ' . $searchFilter);

            $result = ldap_search($this->_l, $this->_ldapBaseDn, $searchFilter, $attributes);

            if ($result) {
                $entries = ldap_get_entries($this->_l, $result);
                foreach ($entries as $entry) {
                    if (!is_array($entry) || empty($entry)) {
                        continue;
                    }
                    if (!isset($entry['objectsid'])) {
                        Yii::warning('No objectsid! ignoring!');
                        continue;
                    }
                    $sid = self::SIDtoString($entry['objectsid'][0]);
                    array_push($return, array_merge(['sid' => $sid, 'dn' => $entry['dn'], 'domainKey' => $i], self::handleEntry($entry)));
                }
            }
            $i++;
        }

        return empty($return) ? [] : $return;


    }

    public static function SIDtoString($ADsid)
    {
        $sid = "S-";
        //$ADguid = $info[0]['objectguid'][0];
        $sidinhex = str_split(bin2hex($ADsid), 2);
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
        return $sid;
    }

    public static function handleEntry($entry)
    {
        $newEntry = [];
        foreach ($entry as $attr => $value) {
            if (is_int($attr) || $attr == 'objectsid' || !isset($value['count'])) {
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