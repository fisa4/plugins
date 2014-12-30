<?php
/**
 * i-MSCP - internet Multi Server Control Panel
 * Copyright (C) 2010-2014 by i-MSCP Team
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
 * @copyright   2010-2014 by i-MSCP Team
 * @author      Sascha Bay <info@space2place.de>
 * @author      Peter Ziergöbel <info@fisa4.de>
 * @author      Ninos Ego <me@ninosego.de>
 * @link        http://www.i-mscp.net i-MSCP Home Site
 * @license     http://www.gnu.org/licenses/gpl-2.0.html GPL v2
 */

/**
 * Create FTP account
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 * @todo: check ftp account limit
 */
function addFtpAccount($resellerId, $postData)
{
    /** @var $db iMSCP_Database */
    $db = iMSCP_Database::getInstance();

    if (empty($postData['username']) || empty($postData['domain']) ||
        empty($postData['password']) || empty($postData['password_repeat']) ||
        empty($postData['home_dir'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain, username, password, password_repeat or home_dir in post data available.'
            )
        )
        );
    }

    $username = clean_input($postData['username']);
    $dmnName = encode_idna($postData['domain']);
    $passwd = clean_input($postData['password']);
    $passwdRepeat = clean_input($postData['password_repeat']);
    $homeDir = clean_input($postData['home_dir']);
    $domainId = getDomainIdByDomain($dmnName);
    $domainAdminId = getDomainAdminIdByDomainId($domainId);


    if (!validates_username($username)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Incorrect username length or syntax.'
            )
        )
        );
    }
    if ($passwd !== $passwdRepeat) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Passwords do not match.'
            )
        )
        );
    } elseif (!checkPasswordSyntax($passwd)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'Passwords syntax is invalid.'
            )
        ));
    }
    // Check for home directory existence
    if ($homeDir != '/' && $homeDir != '') {
        // Strip possible double-slashes
        $homeDir = str_replace('//', '/', $homeDir);
        // Check for updirs '..'
        if (strpos($homeDir, '..') !== false) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => 'Invalid home directory.'
                )
            ));
        }

            $vfs = new iMSCP_VirtualFileSystem($dmnName);
            if (!$vfs->exists($homeDir)) {
                logoutReseller();
                exit(
                createJsonMessage(
                    array(
                        'level' => 'Error',
                        'message' => sprintf('Home directory %s does not exists', $homeDir)
                    )
                )
                );
            }

    }
        // Check that the customer is the owner of the domain for which the ftp Account is added
        if (!customerHasDomain($dmnName, $domainAdminId)) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => sprintf('Customer is not allowed to add FTP account for this domain: %s', $dmnName)
                )
            )
            );
        }
        /** @var $cfg iMSCP_Config_Handler_File */
        $cfg = iMSCP_Registry::get('config');
        $userId = $username . $cfg->FTP_USERNAME_SEPARATOR . decode_idna($dmnName);
        $encryptedPassword = cryptPasswordWithSalt($passwd);
        $shell = $cfg->CMD_SHELL;
        $homeDir = rtrim(str_replace('//', '/', $cfg->FTP_HOMEDIR . '/' . $dmnName . '/' . $homeDir), '/');
        // Retrieve customer uid/gid
        $query = '
				SELECT
					`t1`.`admin_name`, `t1`.`admin_sys_uid`, `t1`.`admin_sys_gid`, `t2`.`domain_disk_limit`,
					count(`t3`.`name`) AS `quota_entry`
				FROM
					`admin` AS `t1`
				LEFT JOIN
					`domain` AS `t2` ON (`t2`.`domain_admin_id` = `t1`.`admin_id` )
				LEFT JOIN
					`quotalimits` AS `t3` ON (`t3`.`name` = `t1`.`admin_name` )
				WHERE
					`t1`.`admin_id` = ?
			';
        $stmt = exec_query($query, $domainAdminId);
        $groupName = $stmt->fields['admin_name'];
        $uid = $stmt->fields['admin_sys_uid'];
        $gid = $stmt->fields['admin_sys_gid'];
        $diskspaceLimit = $stmt->fields['domain_disk_limit'];
        $quotaEntriesExist = ($stmt->fields['quota_entry']) ? true : false;

    iMSCP_Events_Manager::getInstance()->dispatch(
        iMSCP_Events::onBeforeAddFtp,
            array(
                'ftpUserId' => $userId,
                'ftpPassword' => $encryptedPassword,
                'ftpRawPassword' => $passwd,
                'ftpUserUid' => $uid,
                'ftpUserGid' => $gid,
                'ftpUserShell' => $shell,
                'ftpUserHome' => $homeDir
            )
        );
        try {
            $db->beginTransaction();
            // Add ftp user
            $query = "
					INSERT INTO `ftp_users` (
						`userid`, `admin_id`, `passwd`, `rawpasswd`, `uid`, `gid`, `shell`, `homedir`
					) VALUES (
						?, ?, ?, ?, ?, ?, ?, ?
					)
				";
            exec_query(
                $query,
                array($userId, $domainAdminId, $encryptedPassword, $passwd, $uid, $gid, $shell, $homeDir)
            );
            $query = "SELECT `members` FROM `ftp_group` WHERE `groupname` = ? LIMIT 1";
            $stmt = exec_query($query, $groupName);
            // Ftp group
            if (!$stmt->rowCount()) {
                $query = "INSERT INTO `ftp_group` (`groupname`, `gid`, `members`) VALUES (?, ?, ?)";
                exec_query($query, array($groupName, $gid, $userId));
            } else {
                $query = "UPDATE `ftp_group` SET `members` = ? WHERE `groupname` = ?";
                exec_query($query, array("{$stmt->fields['members']},$userId", $groupName));
            }
            // Quota limit
            if (!$quotaEntriesExist) {
                $query = "
						INSERT INTO `quotalimits` (
							`name`, `quota_type`, `per_session`, `limit_type`, `bytes_in_avail`, `bytes_out_avail`,
							`bytes_xfer_avail`, `files_in_avail`, `files_out_avail`, `files_xfer_avail`
						) VALUES (
							?, ?, ?, ?, ?, ?, ?, ?, ?, ?
						)
					";
                exec_query(
                    $query,
                    array($groupName, 'group', 'false', 'hard', $diskspaceLimit * 1048576, 0, 0, 0, 0, 0));
            }
            $db->commit();
        } catch (iMSCP_Exception_Database $e) {
            $db->rollBack();
            if ($e->getCode() == 23000) {
                logoutReseller();
                exit(
                createJsonMessage(
                    array(
                        'level' => 'Error',
                        'message' => 'Account already exists.'
                    )
                )
                );
            } else {
                throw $e;
            }
        }
    iMSCP_Events_Manager::getInstance()->dispatch(
        iMSCP_Events::onAfterAddFtp,
                array(
                    'ftpUserId' => $userId,
                    'ftpPassword' => $encryptedPassword,
                    'ftpRawPassword' => $passwd,
                    'ftpUserUid' => $uid,
                    'ftpUserGid' => $gid,
                    'ftpUserShell' => $shell,
                    'ftpUserHome' => $homeDir
                )
            );
            write_log(sprintf("%s added Ftp account: %s", $_SESSION['user_logged'], $userId), E_USER_NOTICE);
    update_reseller_c_props($resellerId);
    logoutReseller();
    exit(
    createJsonMessage(
        array(
            'level' => 'Success',
            'message' => sprintf('FTP account %s added.', $userId)
        )
    )
    );

}

/**
 * Edit FTP account
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function editFtp($resellerId, $postData)
{
    // TODO: Add code to edit FTP account
}

/**
 * Delete FTP account
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function deleteFtp($resellerId, $postData)
{
    /** @var $cfg, $db iMSCP_Handler_Files */
    $cfg = iMSCP_Registry::get('config');
    $db = iMSCP_Database::getInstance();

    if (empty($postData['username']) || empty($postData['domain']) || empty($postData['log_user'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain, username or log_user in post data available.'
            )
        )
        );
    }

    $domain = encode_idna($postData['domain']);
    $username = clean_input($postData['username']);
    $logUser = clean_input($postData['log_user']);

    $ftpUserId = $username . $cfg->FTP_USERNAME_SEPARATOR . $domain;

    if (!empty($domain) && !empty($username)) {
        $ftpUserId = $username . $cfg->FTP_USERNAME_SEPARATOR . $domain;
        $domainId = getDomainIdByDomain($domain);
        $domainAdminId = getDomainAdminIdByDomainId($domainId);

        iMSCP_Events_Manager::getInstance()->dispatch(
            iMSCP_Events::onBeforeDeleteFtp,
            array('ftpUserId' => $ftpUserId));

        $query = "SELECT `gid` FROM `ftp_users` WHERE `userid` = ? AND `admin_id` = ?";
        $stmt = exec_query($query, array($ftpUserId, $domainAdminId));
        if (!$stmt->rowCount()) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => sprintf('You cannot delete the not available ftp account %s', $ftpUserId)
                )
            )
            );
        }
        $ftpUserGid = $stmt->fields['gid'];

        try {
            $db->beginTransaction();
            $stmt = exec_query("SELECT `groupname`, `members` FROM `ftp_group` WHERE `gid` = ?", $ftpUserGid);
            if ($stmt->rowCount()) {
                $groupName = $stmt->fields['groupname'];
                $members = preg_split('/,/', $stmt->fields['members'], -1, PREG_SPLIT_NO_EMPTY);
                $member = array_search($ftpUserId, $members);
                if (false !== $member) {
                    unset($members[$member]);
                    if (!empty($members)) {
                        exec_query(
                            "UPDATE `ftp_group` SET `members` = ? WHERE `gid` = ?",
                            array(implode(',', $members), $ftpUserGid)
                        );
                    } else {
                        exec_query('DELETE FROM `ftp_group` WHERE `groupname` = ?', $groupName);
                        exec_query('DELETE FROM `quotalimits` WHERE `name` = ?', $groupName);
                        exec_query('DELETE FROM `quotatallies` WHERE `name` = ?', $groupName);
                    }
                }
            }
            exec_query('DELETE FROM `ftp_users` WHERE `userid` = ?', $ftpUserId);

            if(isset($cfg->FILEMANAGER_ADDON) && $cfg->FILEMANAGER_ADDON == 'AjaXplorer') {
                // Quick fix to delete Ftp preferences directory as created by AjaXplorer (Pydio)
                // FIXME: Move this statement at engine level
                $userPrefDir = $cfg->GUI_PUBLIC_DIR . '/tools/filemanager/data/plugins/auth.serial/' . $ftpUserId;
                if(is_dir($userPrefDir)) {
                    utils_removeDir($userPrefDir);
                }
            }
            $db->commit();
            iMSCP_Events_Manager::getInstance()->dispatch(
                iMSCP_Events::onAfterDeleteFtp,
                array('ftpUserId' => $ftpUserId));

            write_log(sprintf("%s: deleted FTP account: %s", $logUser, $ftpUserId), E_USER_NOTICE);
            update_reseller_c_props($resellerId);
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Success',
                    'message' => sprintf('FTP account %s deleted successful', $ftpUserId)
                )
            )
            );
        } catch (iMSCP_Exception_Database $e) {
            $db->rollBack();
            throw $e;
        }
    }
    logoutReseller();
    exit(
    createJsonMessage(
        array(
            'level' => 'Error',
            'message' => sprintf('An error occurred while trying to delete ftp account: %s. Account NOT deleted', $ftpUserId)
        )
    )
    );
}
