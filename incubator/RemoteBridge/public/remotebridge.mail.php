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
 * Create mail account list of a domain
 *
 * @param $resellerId
 * @param $domain
 * @return void
 */
function getMailList($resellerId, $domain)
{
    $domain = strtolower($domain);
    $dmnUsername = encode_idna($domain);

    if (!imscp_domain_exists($dmnUsername, $resellerId)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Domain %s does not exist on this server.', $domain)
            )
        )
        );
    }

    $domainId = getDomainIdByDomain($domain);

    $query = '
		SELECT
			`mail_addr`
		FROM
			`mail_users`
		WHERE
			`domain_id` = ?
	';
    $stmt = exec_query($query, $domainId);

    if (!$stmt->rowCount()) {
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('No admin data available.')
            )
        )
        );
    }

    $result = $stmt->fetchAll();

    echo(
    createJsonMessage(
        array(
            'level' => 'Success',
            'message' => sprintf('Mail account list for domain %s successfully generated.', $domain),
            'data' => $result
        )
    )
    );
}

/**
 * Create mail account
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function addMailAccount($resellerId, $postData)
{
    $db = iMSCP_Registry::get('db');
    $cfg = iMSCP_Registry::get('config');
    $auth = iMSCP_Authentication::getInstance();

    if (empty($postData['domain']) || empty($postData['account']) || (empty($postData['quota']) && $postData['quota'] != 0) || empty($postData['account_type'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain, account or account type in post data available.'
            )
        )
        );
    }

    $domain = encode_idna(strtolower($postData['domain']));
    $account = (isset($postData['account'])) ? clean_input($postData['account']) : '';
    $address = (!empty($account)) ? $account . '@' . $domain : '';
    $accountType = (isset($postData['account_type'])) ? explode(',', str_replace(' ', '', clean_input($postData['account_type']))) : array('normal_mail');
    $quota = (isset($postData['quota']) && in_array('normal_mail', $accountType)) ? clean_input($postData['quota']) * 1048576 : '0';
    $forwardList = (isset($postData['mail_forward']) && in_array('normal_forward', $accountType)) ? explode(',', clean_input($postData['mail_forward'])) : array('');
    $pass = (isset($postData['newmailpass'])) && in_array('normal_mail', $accountType) ? clean_input($postData['newmailpass']) : '_no_';

    if(!chk_email($address)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'This is not a valid mail address.'
            )
        )
        );
    }

    if ($pass != '_no_') {
        remoteBridgecheckPasswordSyntax($pass);
    }

    foreach ($forwardList as $key => &$forwardEmailAddr) {
        $forwardEmailAddr = encode_idna(trim($forwardEmailAddr));
        if (empty($forwardEmailAddr)) {
            unset($forwardList[$key]);
        } elseif (!chk_email($forwardEmailAddr)) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => 'Wrong mail syntax in forward list.'
                )
            )
            );
        } elseif ($forwardEmailAddr == $address) {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'level' => 'Error',
                    'message' => sprintf('You cannot forward %s on itself.', $address)
                )
            )
            );
        }
    }

    $query = '
		SELECT
			domain_id,
			domain_admin_id
		FROM
			domain
		WHERE
			domain_name = ?
	';
    $stmt = exec_query($query, $domain);
    if (!$stmt->rowCount()) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Domain %s is not on this server. Mailaddress %s not added.', $domain, $address)
            )
        )
        );
    }
    $domainId = $stmt->fields['domain_id'];
    $domainAdminId = $stmt->fields['domain_admin_id'];

    $stmt = exec_query("SELECT `mail_id` FROM `mail_users` WHERE `mail_addr` = ?", $address);
    if ($stmt->rowCount()) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Mail address %s already in use.', $address)
            )
        )
        );
    }

    if (in_array('normal_forward', $accountType) && !count($forwardList)) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Please add a forward address for the mail address %s', $address)
            )
        )
        );
    }

    $domainProperties = get_domain_default_props($domainAdminId);
    $domainQuota = $domainProperties['mail_quota'];
    $domainMails = $domainProperties['domain_mailacc_limit'];

    $stmt = exec_query("SELECT `mail_id` FROM `mail_users` WHERE `domain_id` = ?", $domainId);
    $domainCurrentAccounts = $stmt->rowCount();

    if ($domainMails <= $domainCurrentAccounts && $domainMails > '0') {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Cannot add account: %s - You have already used all available mail accounts.', $address)
            )
        )
        );
    }

    $stmt = exec_query("SELECT SUM(`quota`) AS `quota` FROM `mail_users` WHERE `domain_id` = ? AND quota IS NOT NULL", $domainId);
    $domainCurrentQuota = $stmt->fields['quota'];
    $domainQuotaCount = doubleval($domainCurrentQuota) + doubleval($quota);

    if ($domainQuota < $domainQuotaCount && $domainQuota > '0') {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Cannot add account: %s - Not enough quota left.', $address)
            )
        )
        );
    }
    if ($quota == '0') {
        $quota = null;
    }

    try {
        $db->beginTransaction();
        iMSCP_Events_Manager::getInstance()->dispatch(
            iMSCP_Events::onBeforeAddMail,
            array(
                'mailUsername' => $account,
                'MailAddress' => $address
            )
        );

        $query = '
			INSERT INTO `mail_users` (
				`mail_acc`, `mail_pass`, `mail_forward`, `domain_id`, `mail_type`, `sub_id`, `status`,
				`mail_auto_respond`, `mail_auto_respond_text`, `quota`, `mail_addr`
			) VALUES
				(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		';
        exec_query(
            $query,
            array(
                $account, $pass, implode(',', array_unique($forwardList)), $domainId,
                implode(',', array_unique($accountType)), '0', 'toadd',
                '0', NULL, $quota, $address
            )
        );
        $recordId = $db->insertId();

        iMSCP_Events_Manager::getInstance()->dispatch(
            iMSCP_Events::onAfterAddMail,
            array(
                'mailUsername' => $account,
                'mailAddress' => $address,
                'mailId' => $recordId
            )
        );

        send_request();

        /* write_log(
            sprintf(
                "%s add Mail: %s (for domain: %s) via remote bridge.",
                decode_idna($postData['reseller_username']), $address, $domain
            ),
            E_USER_NOTICE
        ); */

        update_reseller_c_props($resellerId);
        $db->commit();

    } catch (iMSCP_Exception_Database $e) {
        $db->rollBack();
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf(
                    'Error while creating New Mail: %s, $s, %s', $e->getMessage(), $e->getQuery(), $e->getCode()
                )
            )
        )
        );
    }

    echo(
    createJsonMessage(
        array(
            'level' => 'Success',
            'message' => sprintf('New email address %s added successful.', $address)
        )
    )
    );
}

/**
 * Check mail account for existence
 *
 * @param array $postData POST data
 * @return void
 */
function checkMail($postData)
{
    if (empty($postData['domain']) || empty($postData['account'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('No domain (%s) or account (%s) in post data available.',
                    $postData['domain'], $postData['account'])
            )
        )
        );
    }

    $domain = encode_idna(strtolower($postData['domain']));
    $account = (isset($postData['account'])) ? clean_input($postData['account']) : '';
    $address = (!empty($account)) ? $account . '@' . $domain : '';

    $stmt = exec_query("SELECT `mail_id` FROM `mail_users` WHERE `mail_addr` = ?", $address);
    if ($stmt->rowCount()) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf('Mail address %s is in use.', $address)
            )
        )
        );
    } else if (!$stmt->rowCount()) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Success',
                'message' => sprintf('Mail address %s isn`t in use.', $address)
            )
        )
        );
    }
}

/**
 * Delete mail account
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function deleteMail($resellerId, $postData)
{
    $db = iMSCP_Registry::get('db');
    $cfg = iMSCP_Registry::get('config');
    $auth = iMSCP_Authentication::getInstance();

    if (empty($postData['domain']) || empty($postData['account'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain or account in post data available.'
            )
        )
        );
    } else {
        $domain = encode_idna(strtolower($postData['domain']));
        $account = (isset($postData['account'])) ? clean_input($postData['account']) : '';
        $address = (!empty($account)) ? $account . '@' . $domain : '';

    }
    $stmt = exec_query("SELECT `mail_id` FROM `mail_users` WHERE `mail_addr` = ?", $address);

    if ($stmt->rowCount()) {
        $mailId = $stmt->fields['mail_id'];
    } else {
        write_log(
            sprintf(
                "%s deletion failed for domain: %s via remote bridge. Mailaddress %s non-existent",
                decode_idna($postData['reseller_username']), $domain, $address
            ),
            E_USER_NOTICE
        );
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf(
                    'Error while deleting mailaddress: %s. Mailaddress non-existent', $address
                )
            )
        )
        );
    }
    try {
        $db->beginTransaction();

        iMSCP_Events_Manager::getInstance()->dispatch(iMSCP_Events::onBeforeDeleteMail, array('mailId' => $mailId));

        exec_query('UPDATE `mail_users` SET `status` = ? WHERE `mail_id` = ?', array('todelete', $mailId));


        exec_query(
            '
				UPDATE
					`mail_users`
				SET
					`status` = ?
				WHERE
					`mail_acc` = ? OR `mail_acc` LIKE ? OR `mail_acc` LIKE ? OR `mail_acc` LIKE ?
			',
            array('todelete', $address, "$address,%", "%,$address,%", "%,$address")
        );

        delete_autoreplies_log_entries($address);

        iMSCP_Events_Manager::getInstance()->dispatch(iMSCP_Events::onAfterDeleteMail, array('mailId' => $mailId));

        send_request();
        write_log(
            sprintf(
                "%s deleted Mail: %s (for domain: %s) via remote bridge.",
                decode_idna($postData['reseller_username']), $address, $domain
            ),
            E_USER_NOTICE
        );
        update_reseller_c_props($resellerId);
        $db->commit();
        echo(
        createJsonMessage(
            array(
                'level' => 'Success',
                'message' => sprintf('Email address %s deleted successful.', $address)
            )
        )
        );

    } catch
    (iMSCP_Exception_Database $e) {
        $db->rollBack();
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => sprintf(
                    'Error while deleting mailaddress: %s, $s, %s', $e->getMessage(), $e->getQuery(), $e->getCode()
                )
            )
        )
        );
    }
}