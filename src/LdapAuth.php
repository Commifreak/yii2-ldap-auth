<?php
/**
 * Created by PhpStorm.
 * User: Robin
 * Date: 07.08.2018
 * Time: 11:21
 */

namespace commifreak\yii2;

use Yii;
use yii\base\BaseObject;
use yii\base\ErrorException;
use yii\base\Exception;
use yii\base\InvalidArgumentException;
use yii\helpers\IpHelper;

class LdapAuth extends BaseObject
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
            'pagedResultsSize' => 0
        ],
    ];

    /**
     * If false (default) any user search would return the whole result.
     * If true, the script checks every user sidHistory and only return results which are newer (migrated).
     * A use case for `true`: You have two domains and user "Foo" was copied from Domain 1 to Domain 2 without deleting it from Domain 1 - now you have 2 results for a search "Foo", but the entry in Domain 2 has a set "sidHistory" with its sid from Domain 1.
     * Setting this tp true will filter out the "Foo" from Domain 1, since its sid is listed in the Domain 2 entry of it.
     *
     * @see https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory
     * @see https://ldapwiki.com/wiki/SIDHistory
     * @var bool
     */
    public $filterBySidhistory = false;

    /**
     * Enable optional object caching. Uses Yii::$app->cache component. Or enable APCu with `forceApcuCache`
     * @var bool
     */
    public $enableCache = false;

    /**
     * Force the use of APCu caching instead of the Yii2 cache component
     * @var bool
     */
    public $forceApcuCache = false;

    /**
     * Time in seconds objects are cached, if `forceApcuCache` is enabled!
     * @var int
     */
    public $apcuCacheTtl = 3600;

    private $_ldapBaseDn;
    private $_l;
    private $_username;
    private $_curDn;
    private $_curDomainHostname;
    private $_curDomainKey;
    private $_singleValuedAttrs;

    public function init()
    {
        parent::init(); // TODO: Change the autogenerated stub

        if (!function_exists('ldap_connect')) {
            throw new Exception("LDAP-extension missing :(");
        }

        // Check for APCu missing if not cli.
        if (php_sapi_name() != 'cli' && $this->enableCache && $this->forceApcuCache && !extension_loaded('apcu')) {
            throw new Exception("Caching is enabled but APCU is not! :(");
        }

        if ($this->enableCache && !$this->forceApcuCache && !isset(Yii::$app->cache)) {
            throw new Exception("Caching is enabled with Yii cache component but its not configured! :(");
        }

        // Sort the domains one time for this run!
        $autoDetectDomainKey = $this->autoDetect();

        if ($autoDetectDomainKey) {
            Yii::debug("AutoDetected domain: #" . $autoDetectDomainKey, __METHOD__);
            $detectedDomain = $this->domains[$autoDetectDomainKey];
            unset($this->domains[$autoDetectDomainKey]);
            $this->domains = [$autoDetectDomainKey => $detectedDomain] + $this->domains;
        } else {
            Yii::debug('AutoDetect was not successful!', __METHOD__);
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

        if (!isset(Yii::$app->request) || !method_exists(Yii::$app->request, 'getUserIP')) {
            Yii::debug("[Autodetect] Skipping autodetection: No getUserIP method found!", __METHOD__);
            return 0;
        }

        Yii::debug('[Autodetect] Started IP autodetection!', __METHOD__);

        if (count($this->domains) <= 1) {
            Yii::debug('[Autodetect] No autodetection needed: Only one domain configured!', __METHOD__);
            return 0;
        }

        Yii::debug('[Autodetect] ' . ($overrideIp ? 'OverrideIp set!' : 'No override IP set!'), __METHOD__);

        $clientIp = $overrideIp ? $overrideIp : Yii::$app->request->getUserIP();

        Yii::debug('[Autodetect] Detected IP: ' . $clientIp, __METHOD__);

        if (empty($clientIp)) {
            Yii::debug('[Autodetect] No client ip detected, skipping auto detection', __METHOD__);
            return false;
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
     * @param integer|false $domainKey The array key of the domain config to use. False to try every single domain. HAS NO EFFECT IF $fetchUserDn IS TRUE!
     * @param boolean $fetchUserDN If true, determine users DN and use that as username
     * @return bool True on success, false on failure.
     * @throws ErrorException
     */
    public function login($username, $password, $domainKey = false, $fetchUserDN = false)
    {

        if ($fetchUserDN) {
            Yii::debug("We have to determine the user DN first!", __METHOD__);
            $userDNSearch = $this->searchUser($username, ['dn'], null, $domainKey, true);
            Yii::debug("fetchUserDN: yes - Result:", __METHOD__);
            Yii::debug($userDNSearch, __METHOD__);

            $firstArrayKey = !$userDNSearch ? false : array_key_first($userDNSearch);

            Yii::debug("userDNSearch result:", __METHOD__);
            Yii::debug($userDNSearch, __METHOD__);

            if ($userDNSearch && count($userDNSearch) == 1 && $firstArrayKey) {
                Yii::debug("Overwrite username " . $username . " to " . $userDNSearch[$firstArrayKey]['dn'], __METHOD__);
                $this->_curDn = $username = $userDNSearch[$firstArrayKey]['dn'];
                $domainKey    = $userDNSearch[$firstArrayKey]['domainKey'];
                Yii::debug("And domainKey to: " . $domainKey, __METHOD__);
            } else {
                Yii::warning("Should overwrite username to DN, but something went wrong while finding the users DN. Leave it as is", __METHOD__);
            }
        }

        if ($this->_l && $domainKey && $domainKey === $this->_curDomainKey) {
            Yii::debug("Reusing current LDAP link identifier", __METHOD__);
            return true;
        }

        if ($domainKey === false) {
            Yii::debug("Using all domains", __METHOD__);
            $domains = $this->domains;
        } else {
            if (!isset($this->domains[$domainKey])) {
                throw new InvalidArgumentException("The domainkey is invalid!");
            }
            Yii::debug("Using domain #" . $domainKey, __METHOD__);
            $domains = [$domainKey => $this->domains[$domainKey]];
        }

        foreach ($domains as $domainKey => $domainData) {

            Yii::debug("Processing domain " . $domainData['hostname'], __METHOD__);

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
                            continue;
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

//            if (!self::serviceping($domainData['hostname'], $ssl ? 636 : null)) {
//                Yii::error('Connection failed!', __METHOD__);
//                continue;
//            }

            $hostPrefix = ($ssl ? 'ldaps://' : 'ldap://') . $domainData['hostname'];
            $port       = $ssl ? 636 : 389;

            Yii::debug('Connecting to ' . $hostPrefix . ', Port: ' . $port, __METHOD__);

            ldap_set_option(null, LDAP_OPT_NETWORK_TIMEOUT, 5);
            $l = @ldap_connect($hostPrefix, $port);
            if (!$l) {
                Yii::warning('Connect failed! ' . ldap_error($l), __METHOD__);
                continue;
            }

            ldap_set_option($l, LDAP_OPT_NETWORK_TIMEOUT, 5);
            ldap_set_option($l, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($l, LDAP_OPT_REFERRALS, 0);

            $bind_dn = strpos($username, '@') === false && strpos($username, ',') === false ? $username . '@' . $domainData['name'] : $username;

            Yii::debug('Trying to authenticate with DN ' . $bind_dn, __METHOD__);

            $connTry   = 0;
            $connected = false;
            do {
                $connTry++;
                $b = @ldap_bind($l, $bind_dn, $password);
                if (!$b && ldap_errno($l) === -1) { // -1 = No TCP connection
                    Yii::warning("Connect try #$connTry failed!", __METHOD__);
                } else {
                    $connected = true;
                }
            } while ($connTry < 3 && !$connected);

            if ($connTry == 3 && !$connected) {
                Yii::error("No answer from LDAP after $connTry tries!", __METHOD__);
            }

            if (!$b) {
                Yii::warning('Bind failed! ' . ldap_error($l) . ' - Errno: ' . ldap_errno($l), __METHOD__);
                continue;
            }

            if (empty($this->_singleValuedAttrs) || !isset($this->_singleValuedAttrs[$domainData['hostname']])) {
                $this->_singleValuedAttrs[$domainData['hostname']] = [];
                Yii::info("Getting attribute type definitions for this domain!", __METHOD__);

                $result = @ldap_read($l, '', "(objectClass=*)", ["subschemaSubentry"]);
                if ($result) {
                    $subSchema = ldap_get_entries($l, $result);
                    Yii::debug("Subschema entry:", __METHOD__);
                    Yii::debug($subSchema, __METHOD__);

                    if (isset($subSchema[0]['subschemasubentry'][0])) {

                        $result = @ldap_read($l, $subSchema[0]['subschemasubentry'][0], "(objectClass=*)", ["attributeTypes"]);

                        if ($result) {
                            $entries = ldap_get_entries($l, $result);
                            foreach ($entries[0]['attributetypes'] as $key => $definition) {
                                if (stripos($definition, 'SINGLE-VALUE') !== false) {
                                    $match = preg_match("/NAME ['\"](.*?)['\"]/", $definition, $matches);
                                    if ($match && isset($matches[1])) {
                                        $this->_singleValuedAttrs[$domainData['hostname']][] = strtolower($matches[1]);
                                    }
                                }
                            }
                        } else {
                            Yii::warning("Could not read attribute Types" . ldap_error($l), __METHOD__);
                        }
                    } else {
                        Yii::warning("No subschema entry found!", __METHOD__);
                    }
                } else {
                    Yii::warning("Could not read subschema entry: " . ldap_error($l), __METHOD__);
                }
                Yii::debug("Single-Value Attributes now: ", __METHOD__);
                Yii::debug($this->_singleValuedAttrs, __METHOD__);
            }

            $this->_l            = $l;
            $this->_ldapBaseDn   = $domainData['baseDn'];
            $this->_username     = $username;
            $this->_curDomainHostname = $domainData['hostname'];
            $this->_curDomainKey = $domainKey;

            return true;
        }

        return false;

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

        $baseDN        = $this->_ldapBaseDn;
        $search_filter = '(&(objectCategory=person)(samaccountname=' . $this->_username . '))';

        if (strpos(strtolower($this->_username), 'cn=') === 0) {
            $baseDN        = $this->_username;
            $search_filter = '(&(objectCategory=person))';
        }

        Yii::debug('[FetchUserData]: BaseDN: ' . $baseDN, __METHOD__);
        Yii::debug('[FetchUserData]: Filter: ' . $search_filter, __METHOD__);


        $result = ldap_search($this->_l, $baseDN, $search_filter, $attributes);

        if ($result) {
            $entries = ldap_get_entries($this->_l, $result);
            if ($entries['count'] > 1 || $entries['count'] == 0) {
                Yii::warning('[FetchUserData]: Found 0 or more than one result!', __METHOD__);
                return false;
            }
            if (!isset($entries[0]) && !isset($entries[0]['objectsid'])) {
                Yii::error('[FetchUserData]: No objectsid!', __METHOD__);
                return false;
            }
            $sid        = self::SIDtoString($entries[0]['objectsid'])[0];
            $sidHistory = isset($entries[0]['sidhistory']) ? self::SIDtoString($entries[0]['sidhistory']) : null;
            return array_merge(['sid' => $sid, 'sidhistory' => $sidHistory], $this->handleEntry($entries[0]));
        } else {
            Yii::error('[FetchUserData]: Search failed: ' . ldap_error($this->_l), __METHOD__);
            return false;
        }
    }

    /**
     * @param string|null $searchFor Search-Term
     * @param array|null $attributes Attributes to get back
     * @param string|null $searchFilter Filter string. Set %searchFor% als placeholder to search for $searchFor
     * @param int|null $domainKey You can provide integer domainkey, this is then used as target domain! Otherwise it searches in all domains
     * @param bool $onlyActiveAccounts SHould the search result only contain active accounts? => https://www.der-windows-papst.de/2016/12/18/active-directory-useraccountcontrol-values/
     * @param bool $allDomainsHaveToBeReachable True: All configured domains need to be reachable in order to get a result. If one is not reachable, false will be returned
     * @param string|null $baseDN Use given BaseDN instead of configured one. This normally requires the exact domainKey being set as well.
     * @return array|false An Array with the results, indexed by their SID - false if an ERROR occured!
     * @throws ErrorException
     */
    public function searchUser(?string $searchFor, ?array $attributes = [], ?string $searchFilter = "", ?int $domainKey = null, bool $onlyActiveAccounts = false, bool $allDomainsHaveToBeReachable = false, ?string $baseDN = null)
    {

        if (empty($attributes)) {
            $attributes = ['sn', 'objectSid', 'sIDHistory', 'givenName', 'mail', 'telephoneNumber', 'l', 'physicalDeliveryOfficeName'];
        }

        array_push($attributes, 'objectSid'); # Push objectsid, regardless of source array, as we need it ALWAYS!
        array_push($attributes, 'sIDHistory'); # Push sIDHistory, regardless of source array, as we need it ALWAYS!

        $onlyActive = '';

        if ($onlyActiveAccounts) {
            $onlyActive = '(|(userAccountControl=16)(userAccountControl=512)(userAccountControl=544)(userAccountControl=66048))'; #https://www.der-windows-papst.de/2016/12/18/active-directory-useraccountcontrol-values/
        }

        if (empty($searchFilter)) {
            $searchFilter = "(&(objectCategory=person) %onlyActive% (|(objectSid=%searchFor%)(sIDHistory=%searchFor%)(samaccountname=*%searchFor%*)(mail=*%searchFor%*)(sn=*%searchFor%*)(givenName=*%searchFor%*)(l=%searchFor%)(physicalDeliveryOfficeName=%searchFor%)))";
        }

        if (empty($searchFor) && strpos($searchFilter, '%searchFor%') !== false) {
            throw new InvalidArgumentException("Search term is empty but the filter has a placeholder set! Set a term or set a new filter.");
        }

        $cacheKey = 'y2ldap_' . md5($searchFor . (implode("", $attributes)) . $searchFilter);
        Yii::debug("Cache-Key: " . $cacheKey, __METHOD__);

        if ($this->enableCache) {
            if (!$this->forceApcuCache) {
                $storedValue = Yii::$app->cache->get($cacheKey);
                if ($storedValue) {
                    Yii::debug("[YII] Returning cached asset", __METHOD__);
                    return $storedValue;
                }
                Yii::debug("Was not cached or invalid", __METHOD__);
            } else {
                if (apcu_exists($cacheKey)) {
                    Yii::debug("Caching enabled and this search is stored!", __METHOD__);
                    $apcuValue = apcu_fetch($cacheKey);
                    if ($apcuValue !== false) {
                        Yii::debug("[APCU] Returning cached asset!", __METHOD__);
                        return $apcuValue;
                    }
                    Yii::warning("Could not return cached asset!", __METHOD__);
                } else {
                    Yii::debug("No cache entry!", __METHOD__);
                }
            }
        } else {
            Yii::debug("Caching disabled", __METHOD__);
        }

        // Default set
        $domains = $this->domains;

        if (is_int($domainKey)) {
            Yii::debug("Static domainkey provided: " . $domainKey, __METHOD__);
            if (!array_key_exists($domainKey, $this->domains)) {
                throw new ErrorException("Provided domainKey does not exist!");
            }
            $domains = [$domainKey => $this->domains[$domainKey]];
        }

        $return = [];
        foreach ($domains as $i => $domain) {
            Yii::debug($domain, __METHOD__);
            if (!$this->login($domain['publicSearchUser'], $domain['publicSearchUserPassword'], $i)) {
                if (empty($this->_l)) {
                    Yii::error('LDAP Connect or Bind error on ' . $domain['hostname'] . ', skipping...', __METHOD__);
                } else {
                    Yii::error('LDAP Connect or Bind error (' . ldap_errno($this->_l) . ' - ' . ldap_error($this->_l) . ') on ' . $domain['hostname'] . ', skipping...');
                }
                if ($allDomainsHaveToBeReachable) {
                    Yii::warning('Abort search, due to error and $allDomainsHaveToBeReachable is true');
                    return false;
                }
                continue;
            }

            $searchFilter = str_replace(["%searchFor%", "%onlyActive%"], [addslashes($searchFor), $onlyActive], $searchFilter);
            $_baseDN = $baseDN ?: $this->_ldapBaseDn;

            Yii::debug('Search-Filter: ' . $searchFilter . " | BaseDN: " . $_baseDN, __METHOD__);

            $result      = ldap_read($this->_l, '', '(objectClass=*)', ['supportedControl']);
            $supControls = ldap_get_entries($this->_l, $result);

            $cookie = '';
            $requestControls = [];
            if (($domain['pagedResultsSize'] ?? 0) > 0) {
                if (!in_array(LDAP_CONTROL_PAGEDRESULTS, $supControls[0]['supportedcontrol'])) {
                    Yii::error("This server does NOT support pagination!", __METHOD__);
                }
                $requestControls = [
                    ['oid' => LDAP_CONTROL_PAGEDRESULTS, 'value' => ['size' => $domain['pagedResultsSize'], 'cookie' => $cookie], 'iscritical' => false]
                ];
            }

            do {
                $result = @ldap_search($this->_l, $_baseDN, $searchFilter, $attributes, 0, -1, -1, LDAP_DEREF_NEVER, $requestControls);
                if (!$result) {
                    // Something is wrong with the search query
                    if (is_null($this->_l)) {
                        Yii::error('ldap_search_error: null', __METHOD__);
                    } else {
                        Yii::error('ldap_search_error: ' . ldap_error($this->_l), __METHOD__);
                    }
                    $this->_l = null;
                    break;
                }
                ldap_parse_result($this->_l, $result, $errcode, $matcheddn, $errmsg, $referrals, $controls);


                if ($result) {
                    $entries = ldap_get_entries($this->_l, $result);
                    Yii::debug('Found entries: ' . ($entries ? $entries["count"] : '0'), __METHOD__);
                    foreach ($entries as $entry) {
                        if (!is_array($entry) || empty($entry)) {
                            continue;
                        }
                        if (!isset($entry['objectsid'])) {
                            Yii::warning('No objectsid! ignoring!', __METHOD__);
                            continue;
                        }
                        $sid        = self::SIDtoString($entry['objectsid'])[0];
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
                        $return[$sid] = array_merge($additionalData, $this->handleEntry($entry));
                    }
                }


                Yii::debug($controls, __METHOD__);
                if (isset($controls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'])) {
                    Yii::debug("Page cookie set!", __METHOD__);
                    // You need to pass the cookie from the last call to the next one
                    $cookie = $controls[LDAP_CONTROL_PAGEDRESULTS]['value']['cookie'];
                } else {
                    Yii::debug("Page cookie NOT set!", __METHOD__);
                    $cookie = '';
                }
                // Empty cookie means last page
            } while (!empty($cookie));


            if ($result) {
                @ldap_free_result($result);
            }
        }

        if ($this->enableCache) {
            Yii::debug("Adding cache entry", __METHOD__);
            if (!$this->forceApcuCache) {
                if (Yii::$app->cache->set($cacheKey, $result)) {
                    Yii::debug("[YII] Caching succeeded!", __METHOD__);
                } else {
                    Yii::warning("[YII] Caching failed!", __METHOD__);
                }
            } else {
                $cacheResult = apcu_store($cacheKey, $return, $this->apcuCacheTtl);
                if (!$cacheResult) {
                    Yii::warning("[APCU] Caching was not successful!", __METHOD__);
                } else {
                    Yii::debug("[APCU] Cached!", __METHOD__);
                }
            }
        } else {
            Yii::debug("Not caching: Disabled", __METHOD__);
        }


        return empty($return) ? [] : $return;


    }

    /**
     * Searches directly for groups and optionally return its members
     * @param string|null $searchFor The search value (like in searchUser). Like (&(objectCategory=group) (|(objectSid=%searchFor%)(cn=*%searchFor%*)))
     * @param array|null $userAttributes
     * @param array $groupAttributes
     * @param string|null $searchFilter The LDAP-Filter
     * @param bool $returnMembers Should the function fetch the group members?
     * @param int|null $domainKey
     * @param bool $onlyActiveAccounts
     * @param bool $allDomainsHaveToBeReachable
     * @param string|null $baseDn
     * @return array|false
     * @throws ErrorException
     */
    public function searchGroup(?string $searchFor, array $groupAttributes = ['dn', 'member'], ?array $userAttributes = ['dn', 'samaccountname', 'mail'], bool $returnMembers = false, ?string $searchFilter = "", ?int $domainKey = null, bool $onlyActiveAccounts = false, bool $allDomainsHaveToBeReachable = false, $baseDn = null)
    {
        if (!in_array('dn', $groupAttributes)) {
            $groupAttributes[] = 'dn';
        }
        if (!in_array('member', $groupAttributes)) {
            $groupAttributes[] = 'member';
        }

        if (empty($searchFilter)) {
            $searchFilter = "(&(objectCategory=group) (|(objectSid=%searchFor%)(cn=%searchFor%)(dn=%searchFor%)))";
        }

        $groups = $this->searchUser($searchFor, $groupAttributes, $searchFilter, $domainKey, $onlyActiveAccounts, $allDomainsHaveToBeReachable, $baseDn);

        if (!$returnMembers) {
            return $groups;
        }

        foreach ($groups as $gkey => $group) {
            if (!isset($group['member'])) {
                continue;
            }
            $groups[$gkey]['users'] = $this->searchUser(null, $userAttributes, '(&(objectCategory=person)(memberof=' . $group['dn'] . '))', $group['domainKey']);
        }

        return $groups;
    }

    /**
     * Performs attribute updates (with special handling of a few attributes, like unicodepwd). A previous ->login is required!
     * @param array $attributes The attribute (array keys are the attribute names, the array values are the attribute values)
     * @param string $dn The DN which should be updated - if not provided, the eventually previous examined one will be used.
     */
    public function updateAttributes($attributes, $dn = null)
    {
        if (empty($dn) && empty($this->_curDn)) {
            Yii::error('provided DN is empty and got no dn from previous login!', __FUNCTION__);
            return false;
        }

        $dn = empty($dn) ? $this->_curDn : $dn;

        if (!is_array($attributes)) {
            Yii::error('Provided attributes are not an array!', __FUNCTION__);
            return false;
        }

        foreach ($attributes as $attribute => $value) {
            Yii::debug('Processing attribute ' . $attribute, __FUNCTION__);

            switch ($attribute) {
                case 'unicodepwd':
                    Yii::info('Patching new password', __FUNCTION__);
                    $password = "\"$value\"";
                    $len      = strlen($password);
                    $newPassw = "";

                    for ($i = 0; $i < $len; $i++) {
                        $newPassw .= "{$password[$i]}\000";
                    }

                    $value = $newPassw;
                    break;
            }

            Yii::debug('Trying to set ' . $attribute . ' to ' . print_r($value, true), __FUNCTION__);

            if (!ldap_mod_replace($this->_l, $dn, [$attribute => $value])) {
                Yii::error('Could not update attribute: ' . ldap_error($this->_l), __FUNCTION__);
                return false;
            }
        }

        return true;

    }

    public static function SIDtoString($ADsid)
    {
        $results = [];
        for ($cnt = 0; $cnt < $ADsid['count']; $cnt++) {
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
                try {
                    $start = 8 + (4 * $i);
                    // X amount of 32Bit (4 Byte) Sub Authorities
                    $sid = $sid . "-" . hexdec($sidinhex[$start + 3] . $sidinhex[$start + 2] . $sidinhex[$start + 1] . $sidinhex[$start]);
                } catch (\Exception $ex) {
                    continue;
                }
            }
//            Yii::debug('Converted SID to: ' . $sid, __METHOD__);
            array_push($results, $sid);
        }
        return $results;
    }

    private function handleEntry($entry)
    {
        $newEntry = [];
        foreach ($entry as $attr => $value) {

            if (is_int($attr) || $attr == 'objectsid' || $attr == 'sidhistory' || !isset($value['count'])) {
                continue;
            }
            $count = $value['count'];

            if ($count > 1 || !in_array(strtolower($attr), $this->_singleValuedAttrs[$this->_curDomainHostname] ?? [])) {
                unset($value['count']);
                $newEntry[$attr] = $value; // Return value as is, because it contains multiple entries
            } else {
                $newEntry[$attr] = $value[0]; // extract first result, because it's the only
            }
        }
        return $newEntry;
    }

    public function getLastError()
    {
        return ldap_error($this->_l);
    }

    public function __destruct()
    {
        if ($this->_l) {
            @ldap_close($this->_l);
            $this->_l = null;
        }
    }

}