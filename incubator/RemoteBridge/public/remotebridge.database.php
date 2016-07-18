<?php
/**
 * i-MSCP - internet Multi Server Control Panel
 * Copyright (C) 2010-2016 by i-MSCP Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @category    iMSCP
 * @package     iMSCP_Plugin
 * @subpackage  RemoteBridge
 * @copyright   2010-2016 by i-MSCP Team
 * @author      Sascha Bay <info@space2place.de>
 * @author      Peter Ziergoebel <info@fisa4.de>
 * @author      Ninos Ego <me@ninosego.de>
 * @link        http://www.i-mscp.net i-MSCP Home Site
 * @license     http://www.gnu.org/licenses/gpl-2.0.html GPL v2
 */

/**
 * Create new database user
 *
 * @param string $dbName POST data
 * @return bool
 */
function isDatabase($dbName)
{
    $stmt = exec_query('SHOW DATABASES LIKE ?', $dbName);
    return (bool)$stmt->rowCount();
}

/**
 * Does the given SQL user already exists?
 *
 * @param string $sqlUser SQL user name
 * @param string $sqlUserHost SQL user host
 * @return bool TRUE if the given sql user already exists, FALSE otherwise
 */
function isSqlUser($sqlUser, $sqlUserHost)
{
    $stmt = exec_query('SELECT User FROM mysql.user WHERE User = ? AND Host = ?', array($sqlUser, $sqlUserHost));
    return (bool)($stmt->rowCount());
}

/**
 * Create new database user
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function addSqlUser($resellerId, $postData)
{
    if (empty($postData['domain']) || empty($postData['sql_user']) ||
        empty($postData['password']) || empty($postData['password_confirmation']) ||
        empty($postData['db_name'])
    ) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain, sql_user, password, password_confirmation or db_name in post data available.'
            )
        )
        );
    }
    $domain = (isset($postData['domain'])) ? encode_idna($postData['domain']) : '';
    $domainId = getDomainIdByDomain($domain);
    $domainAdminId = getDomainAdminIdByDomainId($domainId);
    $sqlUser = (isset($postData['sql_user'])) ? clean_input($postData['sql_user']) : '';
    $sqlUserPassword = (isset($postData['password'])) ? clean_input($postData['password']) : '';
    $sqlUserPasswordConfirm = (isset($postData['password_confirmation'])) ?
        clean_input($postData['password_confirmation']) : '';
    $useExistingUser = (isset($postData['use_existing_user'])) ? $postData['use_existing_user'] : '';
    $logUser = (isset($postData['log_user'])) ? clean_input($postData['log_user']) : $domain;

    $domainProperties = get_domain_default_props($domainAdminId);
    $maxDbUser = $domainProperties['domain_sqlu_limit'];

    $stmt = exec_query(
        'SELECT COUNT(`sqlu_id`) AS `count` FROM `sql_user` WHERE sqld_id = (SELECT sqld_id FROM sql_database WHERE `domain_id` = ?)', $domainId
    );
    $currentDatabaseUser =  $stmt->fields['count'];
    
    if($maxDbUser != '0' && $currentDatabaseUser >= $maxDbUser){
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'You have reached the max. database user limit'
            )
        )
        );
    }

    if ($useExistingUser == FALSE) { // Add new SQL user as specified in input data
        $sqlUserHost = encode_idna(clean_input($postData['user_host']));
        if (
            $sqlUserHost != '%' && $sqlUserHost != 'localhost' &&
            !iMSCP_Validate::getInstance()->hostname(
                $sqlUserHost, array('allow' => Zend_Validate_Hostname::ALLOW_DNS | Zend_Validate_Hostname::ALLOW_IP)
            )
        ) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => sprintf('Invalid SQL user host: %s.', $sqlUserHost)
                )
            )
            );
        }
        if (!checkPasswordSyntax($sqlUserPassword)) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => 'Only printable characters from the ASCII table (not extended), excepted the space, are allowed.'
                )
            )
            );
        }
        if ($sqlUserPassword !== $sqlUserPasswordConfirm) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => 'Passwords do not match.'
                )
            )
            );
        }
        // we'll use domain_id in the name of the database;
        if (
            isset($postData['use_dmn_id']) && $postData['use_dmn_id'] == TRUE && isset($postData['id_pos'])
            && $postData['id_pos'] == 'start'
        ) {
            $sqlUser = $domainId . '_' . clean_input($sqlUser);
        } elseif (
            isset($postData['use_dmn_id']) && $postData['use_dmn_id'] == TRUE && isset($postData['id_pos']) &&
            $postData['id_pos'] == 'end'
        ) {
            $sqlUser = clean_input($sqlUser) . '_' . $domainId;
        } else {
            $sqlUser = clean_input($sqlUser);
        }
    } else { // Using existing SQL user as specified in input data
        $stmt = exec_query(
            'SELECT sqld_id, sqlu_host, sqlu_pass FROM sql_user WHERE sqlu_name = ?', $sqlUser
        );
        if (!$stmt->rowCount()) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => 'User not available. Please set use_existing_user to FALSE and try again.'
                )
            )
            );
        }
        $row = $stmt->fetchRow(PDO::FETCH_ASSOC);
        $sqlUserHost = $row['sqlu_host'];
        $sqlUserPassword = $row['sqlu_pass'];

    }
    # Check for username length
    if (strlen($sqlUser) > 16) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Username is too long. Max 16 characters are allowed'
            )
        )
        );
    }
    // Check for unallowed character in username
    if (preg_match('/[%|\?]+/', $sqlUser)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Wildcards such as %% and ? are not allowed in username.'
            )
        )
        );
    }
    // Ensure that SQL user doesn't already exists
    if ($useExistingUser == FALSE && isSqlUser($sqlUser, $sqlUserHost)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('SQL user %s already exits.', $sqlUser . '@' . decode_idna($sqlUserHost))
            )
        )
        );
    }
    # Retrieve database to which SQL user should be assigned
    $stmt = exec_query(
        'SELECT sqld_id, sqld_name FROM sql_database WHERE domain_id = ?', array($domainId)
    );
    if (!$stmt->rowCount()) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Database not exists.'
            )
        )
        );
    } else {

        $dbName = $stmt->fields['sqld_name'];
        $dbName = preg_replace('/([_%\?\*])/', '\\\$1', $dbName);
        $databaseId = $stmt->fields['sqld_id'];

        $sqlUserCreated = false;
        iMSCP_Events_Manager::getInstance()->dispatch(iMSCP_Events::onBeforeAddSqlUser);
        // Here we cannot use transaction because the GRANT statement cause an implicit commit
        // We execute the GRANT statements first to let the i-MSCP database in clean state if one of them fails.
        try {
            exec_query(
                'GRANT ALL PRIVILEGES ON ' . quoteIdentifier($dbName) . '.* TO ?@? IDENTIFIED BY ?',
                array($sqlUser, $sqlUserHost, $sqlUserPassword)
            );
            $sqlUserCreated = true;
            exec_query(
                'INSERT INTO sql_user (sqld_id, sqlu_name, sqlu_host, sqlu_pass) VALUES (?, ?, ?,?)',
                array($databaseId, $sqlUser, $sqlUserHost, $sqlUserPassword)
            );
        } catch (iMSCP_Exception_Database $e) {
            if ($sqlUserCreated) {
                try { // We don't care about result here - An exception is throw in case the user do not exists
                    exec_query('DROP USER ?@?', $sqlUser, $sqlUserHost);
                } catch (iMSCP_Exception_Database $x) {
                }
            }
            throw $e;
        }
        iMSCP_Events_Manager::getInstance()->dispatch(iMSCP_Events::onAfterAddSqlUser);
        write_log(sprintf("%s added new SQL user: %s", $logUser, tohtml($sqlUser)), E_USER_NOTICE);
        update_reseller_c_props($resellerId);
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Success',
                'message' => sprintf('SQL user %s successfully added.', $sqlUser)
            )
        )
        );
    }
}

/**
 * Delete database user
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function deleteSqlUser($resellerId, $postData)
{
    if (empty($postData['domain']) || empty($postData['sql_user'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain or sql_user in post data available.'
            )
        )
        );
    }

    $stmt = exec_query(
        'SELECT sqlu_id FROM sql_user WHERE sqlu_name = ?',$postData['sql_user']
    );
    if (!$stmt->rowCount()) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'User not exists.'
            )
        )
        );
    }
    $domain = (isset($postData['domain'])) ? encode_idna($postData['domain']) : '';
    $sqlUserId = $stmt->fields['sqlu_id'];
    $logUser = (isset($postData['log_user'])) ? encode_idna($postData['log_user']) : $domain;
    $domainId = getDomainIdByDomain($domain);
    $domainAdminId = getDomainAdminIdByDomainId($domainId);
    $domainProperties = get_domain_default_props($domainAdminId);

    if (sql_delete_user($domainId, $sqlUserId)) {
        write_log(sprintf("%s deleted SQL user with ID %d",$logUser, $sqlUserId), E_USER_NOTICE);
        update_reseller_c_props($resellerId);
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Success',
                'message' => 'Sql user successfully deleted.'
            )
        )
        );
    }
    else{
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Could not delete Sql user.'
            )
        )
        );
    }
}

/**
 * Create new database 
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function addSqlDb($resellerId, $postData)
{
    $db = iMSCP_Registry::get('db');

    if (empty($postData['domain']) || empty($postData['db_name'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain or db_name in post data available.'
            )
        )
        );
    }
    if (isset($postData['use_prefix']) && $postData['use_prefix'] == 'yes') {
        if (empty($postData['db_prefix']) || empty($postData['prefix_pos'])) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => 'No db_prefix or prefix_pos in post data available.'
                )
            )
            );
        }
    }

    $domain = encode_idna($postData['domain']);
    $usePrefix = (isset($postData['use_prefix'])) ? clean_input($postData['use_prefix']) : '';
    $dbPrefix = (isset($postData['db_prefix'])) ? clean_input($postData['db_prefix']) : '';
    $prefixPos = (isset($postData['prefix_pos'])) ? clean_input($postData['prefix_pos']) : '';
    $dbName = (isset($postData['db_name'])) ? clean_input($postData['db_name']) : '';
    $logUser = (isset($postData['log_user'])) ? clean_input($postData['log_user']) : $domain;
    $domainId = getDomainIdByDomain($domain);
    $domainAdminId = getDomainAdminIdByDomainId($domainId);
    $domainProperties = get_domain_default_props($domainAdminId);
    $maxDbAccounts = $domainProperties['domain_sqld_limit'];

    $stmt = exec_query(
        'SELECT COUNT(`sqld_id`) AS `count` FROM `sql_database` WHERE `domain_id` = ?', $domainId
    );

    $currentDatabases =  $stmt->fields['count'];
    if($currentDatabases >= $maxDbAccounts && $maxDbAccounts != '0'){
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'You have reached the max. database limit'
            )
        )
        );
    }

    if ($usePrefix == 'yes' && $prefixPos === 'start') {
        $dbName = $dbPrefix . "_" . $dbName;
    } else if ($usePrefix == 'yes' && $prefixPos === 'end') {
        $dbName = $dbName . "_" . $dbPrefix;
    } if ($usePrefix == 'no') {
        $dbName = $dbName;
    } 


    if (strlen($dbName) > 64) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Database name: %s is too long. Max length 64 characters', $dbName)
            )
        )
        );
    }
    if ($dbName == 'test' || isDatabase($dbName)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Database name: %s is not available. (The database could be already assigned to another user.)', $dbName)
            )
        )
        );
    }
    // Are wildcards used?
    if (preg_match('/[%|\?]+/', $dbName)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Wildcards such as % and ? are not allowed.'
            )
        )
        );
    }
    $responses = iMSCP_Events_Manager::getInstance()->dispatch(
        iMSCP_Events::onBeforeAddSqlDb, array('dbName' => $dbName
        )
    );
    if (!$responses->isStopped()) {
        // Here we cannot start transaction before the CREATE DATABASE statement because its cause an implicit commit
        $dbCreated = false;
        try {
            execute_query('CREATE DATABASE IF NOT EXISTS ' . quoteIdentifier($dbName));
            $dbCreated = true;
            exec_query('INSERT INTO sql_database (domain_id, sqld_name) VALUES (?, ?)', array($domainId, $dbName));
            write_log($logUser . ": added new SQL database: " . tohtml($dbName), E_USER_NOTICE);
            update_reseller_c_props($resellerId);
            iMSCP_Events_Manager::getInstance()->dispatch(
                iMSCP_Events::onAfterAddSqlDb, array('dbName' => $dbName)
            );
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Success',
                    'message' => 'SQL database successfully added.'
                )
            )
            );
        } catch (iMSCP_Exception_Database $e) {
            if ($dbCreated) {
                execute_query('DROP DATABASE IF EXISTS ' . quoteIdentifier($dbName));
            }
            $db->rollBack();
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => sprintf(
                        'Error while creating user: %s, $s, %s', $e->getMessage(), $e->getQuery(), $e->getCode()
                    )
                )
            )
            );
        }
    }
}

/**
 * Edit database user password
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function editSqlUserPassword($resellerId, $postData)
{
    if (empty($postData['domain']) || empty($postData['sql_user']) ||
	empty($postData['password']) || empty($postData['password_confirmation'])
    ) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain, password, password_confirmation or sql_user in post data available.'
            )
        )
        );
    }
    $logUser = (isset($postData['log_user'])) ? clean_input($postData['log_user']) : encode_idna($postData['domain']);
    $sqlUserName = (isset($postData['sql_user'])) ? clean_input($postData['sql_user']) : '';
    list(
        $sqlUserId, $oldSqlUserHost, $oldSqlPassword
        ) = getDbUserValues($sqlUserName);
    $password = (isset($postData['password'])) ? clean_input($postData['password']) : $oldSqlPassword;
    $passwordConfirmation = (isset($postData['password_confirmation'])) ? clean_input($postData['password_confirmation']) : $oldSqlPassword;
    $sqlUserHost = (isset($postData['user_host'])) ? clean_input($postData['user_host']) : $oldSqlUserHost;

    if ($password === '') {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Password cannot be empty.'
            )
        )
        );
    }
    if ($password !== $passwordConfirmation) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Passwords do not match.'
            )
        )
        );
    }
    if (!checkPasswordSyntax($password)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Passwords syntax do not match.'
            )
        )
        );
    }

    if ($sqlUserId <= 0) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'User not exists'
            )
        )
        );
    }

    $passwordUpdated = false;
    iMSCP_Events_Manager::getInstance()->dispatch(
        iMSCP_Events::onBeforeEditSqlUser, array('sqlUserId' => $sqlUserId));
    try {
        // Update SQL user password in the mysql system tables;
        exec_query("SET PASSWORD FOR ?@? = PASSWORD(?)", array($sqlUserName, $oldSqlUserHost, $password));
	$passwordUpdated = true;

        // Update user password in the i-MSCP sql_user table;
        exec_query(
            'UPDATE sql_user SET sqlu_pass = ? WHERE sqlu_name = ? AND sqlu_host = ?',
            array($password, $sqlUserName, $oldSqlUserHost)
        );
        write_log(
            sprintf("%s updated %s@%s SQL user password.", $logUser, $sqlUserName, $oldSqlUserHost),
            E_USER_NOTICE
        );
        update_reseller_c_props($resellerId);
        iMSCP_Events_Manager::getInstance()->dispatch(
            iMSCP_Events::onAfterEditSqlUser, array('sqlUserId' => $sqlUserId));
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Success',
                'message' => 'SQL user password successfully updated.'
            )
        )
        );
    } catch (iMSCP_Exception_Database $e) {
        if ($passwordUpdated) {
            try {
                exec_query("SET PASSWORD FOR ?@? = PASSWORD(?)", array($sqlUserName, $oldSqlUserHost, $oldSqlPassword));
            } catch (iMSCP_Exception_Database $f) {
            }
        }
    }
}

/**
 * Delete database 
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function deleteSqlDb($resellerId, $postData)
{
    if (empty($postData['domain']) || empty($postData['db_name'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain or db_name in post data available.'
            )
        )
        );
    }
    $domain = (isset($postData['domain'])) ? $postData['domain'] : '';
    $dbName = (isset($postData['db_name'])) ? $postData['db_name'] : '';
    $domainId = getDomainIdByDomain($domain);
    $databaseId = intval(getDbId($domainId, $dbName));
    $logUser = (isset($postData['logUser']) ? $postData['logUser'] : $domain);

    if (delete_sql_database($domainId, $databaseId)) {
        write_log(sprintf("%s deleted SQL database with ID %s", $logUser, $databaseId), E_USER_NOTICE);
        update_reseller_c_props($resellerId);
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Success',
                'message' => sprintf('SQL database %s successfully deleted.', $dbName)
            )
        )
        );
    }
    logoutReseller();
    exit(
    createJsonMessage(
        array(
            'level' => 'Error',
            'message' => sprintf('Could not delete SQL database %s.', $dbName)
        )
    )
    );
}

/**
 * Get database list
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function getSqlDb($postData)
{
    if (empty($postData['domain'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain or db_name in post data available.'
            )
        )
        );
    }
    $domain = (isset($postData['domain'])) ? encode_idna($postData['domain']) : '';
    $domainId = getDomainIdByDomain($domain);

    $stmt = exec_query('SELECT sqld_name FROM sql_database WHERE domain_id = ?',$domainId);

    if (!$stmt->rowCount()) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('No database available.')
            )
        )
        );
    }

    $result = $stmt->fetchAll();

    echo(
    createJsonMessage(
        array(
            'level' => 'Success',
            'message' => sprintf('Database list successfully generated for domain %s ',$domain),
            'data' => $result
        )
    )
    );
}
