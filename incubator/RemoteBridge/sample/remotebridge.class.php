<?php

class remoteBridge
{

    private $bridgeKey = ''; // Your bridge key
    private $ResellerUsername = ''; // Your reseller username
    private $ResellerPassword = ''; // Your reseller password
    private $RemoteBridge = 'http://admin.your.server.tld/remotebridge.php'; // Your remotebridge server URL

    function __construct()
    {

    }

    function curl_send($dataToEncrypt)
    {

        $ch = curl_init($this->RemoteBridge);

        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, 'key=' . $this->bridgeKey . '&data=' . $this->dataEncryption($dataToEncrypt, $this->ResellerUsername));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        $httpResponse = curl_exec($ch);

        curl_close($ch);

        return $httpResponse;
    }

    function dataEncryption($dataToEncrypt, $resUsername)
    {
        return strtr(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($resUsername), serialize($dataToEncrypt), MCRYPT_MODE_CBC, md5(md5($resUsername)))), '+/=', '-_,');
    }

    function addUser($domain, $adminPass, $email, $hostingPlan, $fName, $lName, $firm, $zip)
    {
        $dataToEncrypt = array(
            'action' => 'create_user',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'hosting_plan' => $hostingPlan,
            'admin_pass' => $adminPass,
            'email' => $email,
            'fname' => $fName,
            'lname' => $lName,
            'firm' => $firm,
            'zip' => $zip,
            'domain' => $domain
        );
        return $this->curl_send($dataToEncrypt);
    }

    function updateDomain($domain, $email, $hostingPlan = '')
    {
        $dataToEncrypt = array(
            'reseller_username'     => $this->ResellerUsername,
            'reseller_password'     => $this->ResellerPassword,
            'bridge_key'            => $this->bridgeKey,
            'hosting_plan'          => $hostingPlan,
            'domain'                => $domain,
            'email'                 => $email
        );

        return $this->curl_send($dataToEncrypt);
    }

    function getUser()
    {
        $dataToEncrypt = array(
            'action' => 'get_users',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey
        );
        return $this->curl_send($dataToEncrypt);
    }

    function addSubdomain($subdomain, $domain)
    {
        $dataToEncrypt = array(
            'action' => 'add_subdomain',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'subdomain' => $subdomain,
            'domain' => $domain
        );
        return $this->curl_send($dataToEncrypt);
    }

    function checkSubdomain($subdomain, $domain)
    {
        $dataToEncrypt = array(
            'action' => 'check_subdomain',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'subdomain' => $subdomain,
            'domain' => $domain
        );
        return $this->curl_send($dataToEncrypt);
    }

    function checkMail($account, $domain)
    {
        $dataToEncrypt = array(
            'action' => 'check_mail',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'account' => $account,
            'domain' => $domain
        );
        return $this->curl_send($dataToEncrypt);
    }

    function deleteMail($account, $domain)
    {
        $dataToEncrypt = array(
            'action' => 'delete_mail',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'account' => $account,
            'domain' => $domain
        );
        return $this->curl_send($dataToEncrypt);
    }

    function addMail($account, $domain, $pass, $quota, $accountType = 'normal_mail', $forward = '')
    {
        $dataToEncrypt = array(
            'action' => 'add_mail',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'account' => $account,
            'mail_pass' => $pass,
            'quota' => $quota,
            'mail_forward' => $forward,
            'account_type' => $accountType

        );
        return $this->curl_send($dataToEncrypt);
    }

    function collectUsageData($domain)
    {
        $dataToEncrypt = array(
            'action' => 'collectusagedata',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain
        );
        return $this->curl_send($dataToEncrypt);
    }

    function getMail($domain)
    {
        $dataToEncrypt = array(
            'action' => 'get_mails',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain
        );

        return $this->curl_send($dataToEncrypt);
    }

    function addFtpAccount($domain, $username, $password, $passwordRepeat, $homeDir, $domainType = 'dmn')
    {
        $dataToEncrypt = array(
            'action' => 'add_ftp',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'domain_type' => $domainType,
            'username' => $username,
            'password' => $password,
            'password_repeat' => $passwordRepeat,
            'home_dir' => $homeDir
        );
        return $this->curl_send($dataToEncrypt);
    }

    function editFtpAccount($domain, $username, $password, $passwordRepeat, $homeDir, $domainType = 'dmn')
    {
        $dataToEncrypt = array(
            'action' => 'edit_ftp',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'domain_type' => $domainType,
            'username' => $username,
            'password' => $password,
            'password_repeat' => $passwordRepeat,
            'home_dir' => $homeDir
        );
        return $this->curl_send($dataToEncrypt);
    }

    function deleteFtpAccount($domain, $username, $logUser)
    {
        $dataToEncrypt = array(
            'action' => 'delete_ftp',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'username' => $username,
            'log_user' => $logUser
        );
        return $this->curl_send($dataToEncrypt);
    }

    function addSqlDb($domain, $dbName, $logUser, $usePrefix = FALSE, $prefixPos = 'start', $dbPrefix = '')
    {
        $dataToEncrypt = array(
            'action' => 'add_sql_db',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'db_name' => $dbName,
            'use_prefix' => $usePrefix,    // TRUE / FALSE
            'prefix_pos' => $prefixPos,        // start / end
            'db_prefix' => $dbPrefix,        // any value
            'log_user' => $logUser
        );
        return $this->curl_send($dataToEncrypt);
    }

    function deleteSqlDb($domain, $dbName, $logUser)
    {
        $dataToEncrypt = array(
            'action' => 'delete_sql_db',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'db_name' => $dbName,
            'log_user' => $logUser
        );
        return $this->curl_send($dataToEncrypt);
    }

    function getSqlDb($domain)
    {
        $dataToEncrypt = array(
            'action' => 'get_sql_db',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain
        );
        return $this->curl_send($dataToEncrypt);
    }

    function editSqlUserPass($domain, $sqlUserName, $password, $passwordConfirm, $logUser)
    {
        $dataToEncrypt = array(
            'action' => 'edit_sql_user_pass',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'password' => $password,
            'password_confirmation' => $passwordConfirm,
            'sql_user' => $sqlUserName,
            'log_user' => $logUser
        );
        return $this->curl_send($dataToEncrypt);
    }

    function addSqlUser($domain,$dbName, $sqlUserName, $password, $passwordConfirm, $logUser,
                        $host = 'localhost', $existingUser = FALSE, $useDmnId = FALSE, $dmnPos = 'start')
    {
        $dataToEncrypt = array(
            'action' => 'add_sql_user',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'password' => $password,
            'password_confirmation' => $passwordConfirm,
            'sql_user' => $sqlUserName,
            'use_existing_user' => $existingUser,      // TRUE/FALSE
            'use_dmn_id' => $useDmnId,                  // TRUE/FALSE
            'id_pos' => $dmnPos,                         // start/end
            'log_user' => $logUser,
            'user_host' => $host,
            'db_name' => $dbName
        );
        return $this->curl_send($dataToEncrypt);
    }

    function deleteSqlUser($domain,$sqlUserName,$logUser)
    {
        $dataToEncrypt = array(
            'action' => 'delete_sql_user',
            'reseller_username' => $this->ResellerUsername,
            'reseller_password' => $this->ResellerPassword,
            'bridge_key' => $this->bridgeKey,
            'domain' => $domain,
            'sql_user' => $sqlUserName,
            'log_user' => $logUser
        );
        return $this->curl_send($dataToEncrypt);
    }
}
