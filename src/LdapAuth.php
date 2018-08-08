<?php
/**
 * Created by PhpStorm.
 * User: Robin
 * Date: 07.08.2018
 * Time: 11:21
 */

namespace commifreak\yii2;

use Yii;
use yii\helpers\IpHelper;
use yii\base\Exception;

class LdapAuth
{

    /**
     * Defines the doamins to use.
     * @var array
     */
    public $domains = [
        'example' => ['hostname' => 'example.tld', 'autodetectIps' => ['127.0.0.1', '123.123.0.0/16']]
    ];

    public $ldapBaseDn = "DC=example,DC=tld";

    private $_l;
    private $_username;




    public function __construct()
    {

        if(!function_exists('ldap_connect')) {
            throw new Exception("LDAP-extension missing :(");
        }

    }


    public function autoDetect($overrideIp = false) {
        $clientIp = $overrideIp ? $overrideIp : (isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR']);

        foreach ($this->domains as $domainName => $config) {
            Yii::debug('Processing '.$domainName);
            foreach ($config['autodetectIps'] as $ip) {
                if (IpHelper::inRange($clientIp, $ip)) {
                    Yii::debug('Domain found!');
                    $useDomain = $domainName;
                    break;
                }
            }
            if (isset($useDomain)) {
                break;
            }
        }

        if(isset($useDomain)) {
            return array_search($useDomain, array_keys($this->domains));
        } else {
            return false;
        }
    }


    public function login($username, $password, $domainKey) {


        $domainData = $this->domains[$domainKey];
        $domain = key($this->domains[$domainKey]);

        Yii::debug('Trying to connect to Domain #'.$domainKey.' ('.$domainData['hostname'].')');

        $l = @ldap_connect($domainData['hostname']);
        if(!$l) {
            return false;
        }

        ldap_set_option($l, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($l, LDAP_OPT_REFERRALS, 0);


        $b = @ldap_bind($l, $username.'@'.$domain, $password);

        if(!$b) {
            return false;
        }

        $this->_l = $l;
        $this->ldapBaseDn = $domainData['baseDn'];
        $this->_username = $username;






    }

    public function fetchUserSid() {
        $search_filter = '(&(objectCategory=person)(samaccountname='.$this->_username.'))';

        $attributes = ['sn', 'objectSid', 'givenName', 'mail', 'telephoneNumber'];

        $result = ldap_search($this->_l, $this->ldapBaseDn, $search_filter, $attributes);

        if($result) {
            $entries = ldap_get_entries($this->_l, $result);
            $sid = self::SIDtoString($entries[0]['objectsid'][0]);
            return $sid;
        }
    }

    public static function SIDtoString($ADsid)
    {
        $sid = "S-";
        //$ADguid = $info[0]['objectguid'][0];
        $sidinhex = str_split(bin2hex($ADsid), 2);
        // Byte 0 = Revision Level
        $sid = $sid.hexdec($sidinhex[0])."-";
        // Byte 1-7 = 48 Bit Authority
        $sid = $sid.hexdec($sidinhex[6].$sidinhex[5].$sidinhex[4].$sidinhex[3].$sidinhex[2].$sidinhex[1]);
        // Byte 8 count of sub authorities - Get number of sub-authorities
        $subauths = hexdec($sidinhex[7]);
        //Loop through Sub Authorities
        for($i = 0; $i < $subauths; $i++) {
            $start = 8 + (4 * $i);
            // X amount of 32Bit (4 Byte) Sub Authorities
            $sid = $sid."-".hexdec($sidinhex[$start+3].$sidinhex[$start+2].$sidinhex[$start+1].$sidinhex[$start]);
        }
        return $sid;
    }

}