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
 * @link        http://www.i-mscp.net i-MSCP Home Site
 * @license     http://www.gnu.org/licenses/gpl-2.0.html GPL v2
 */

/**
 * Create Mailaccount list of a domain
 *
 * @param $resellerId
 * @param $domain
 * @return Mailaccount list
 */

function getMailList($resellerId, $domain)
{
	if (empty($domain)) {
                logoutReseller();
                exit(
                createJsonMessage(
                array(
                'level' => 'Error',
                'message' => 'No domain in post data available.'
                                )
                        )
                );
        }
        
        $domain = strtolower($domain);
        $dmnUsername = encode_idna($domain);

        if (! imscp_domain_exists($dmnUsername, $resellerId)) {
                logoutReseller();
                exit(
                        createJsonMessage(
                                array(
                                        'level' => 'Error',
                                        'message' => sprintf('Domain %s not exist on this server.', $domain)
                                )
                        )
                );
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
        $domainId = $stmt->fields['domain_id'];
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
        } else {
                $result = $stmt->fetchAll();

                echo(
                createJsonMessage(
                        array(
                                'level' => 'Success',
                                'message' => sprintf('Mailaccount list for domain %s successfully generated.', $domain),
                                'data' => $result
                        )
                )
                );

        }
}

/**
 * Create mail account
 *
 * @param int $resellerId Reseller unique identifier
 * @param $domain Users domain name
 * @param $account Mailaccount name
 * @param $quota Mailbox quota
 * @param $newmailpass password for new mailaccount
 * @param $account_type Type of mailaccount 
 * @param $mail_forward Forwarding mailaddress
 * @return void
 */
function addMailAccount($resellerId, $domain, $account, $quota, $newmailpass, $account_type, $mail_forward)
{
	$db = iMSCP_Registry::get('db');
	$cfg = iMSCP_Registry::get('config');
	$auth = iMSCP_Authentication::getInstance();

	if (empty($domain) || empty($account) || empty($newmailpass) || $quota == '' || empty($account_type)) {
		logoutReseller();
		exit(
		createJsonMessage(
			array(
				'level' => 'Error',
				'message' => 'Hello, no domain ('.$domain.'), Quota ('.$quota.'), users new email accountname ('.$account.'), email password ('.$newmailpass.') or account type ('.$account_type.') in post data available.'
			)
		)
		);
	}

	$domain = strtolower($domain);
	$domain = encode_idna($domain);
	$mailAccount = (isset($account)) ? clean_input($account) : '';
	$newEmail = (isset($account)) ? clean_input($account.'@'.$domain) : '';
	$newEmailPass = (isset($newmailpass)) ? clean_input($newmailpass) : '';
        $account_type = (isset($account_type)) ? clean_input($account_type) : 'normal_mail';
	$quota = (isset($quota)) ? clean_input($quota) : '0';
	$quota = $quota * 1024*1024;
	$forwardList = (isset($mail_forward)) ? clean_input($mail_forward) : '';;

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
	$domainId = $stmt->fields['domain_id'];
        $domainAdminId = $stmt->fields['domain_admin_id'];

        $stmt = exec_query("SELECT `mail_id` FROM `mail_users` WHERE `mail_addr` = ?", $newEmail);
	if ($stmt->rowCount()) {
	logoutReseller();
        exit(
        createJsonMessage(
                array(
                        'level' => 'Error',
                        'message' => sprintf('Mailaddress: %s already in use.', $newEmail)
                )
        )
        );
	
	}

	if (($account_type == 'normal_forward' || $account_type == 'normal_mail,normal_forward') && empty($mail_forward)) {
		logoutReseller();
		exit(
		createJsonMessage(
			array(
				'level' => 'Error',
				'message' => sprintf('Please add a forward address for the mailaddress: %s', $newEmail)
				)
			)
		);
	}

        $domainProperties = get_domain_default_props($domainAdminId);
        $domainQuota = $domainProperties['mail_quota'];
	$domainMails = $domainProperties['domain_mailacc_limit'];
	
	$stmt = exec_query("SELECT `mail_id` FROM `mail_users` WHERE `domain_id` = ?", $domainId);
	$domainCurrentAccounts = $stmt->rowCount();

	if($domainMails <= $domainCurrentAccounts && $domainMails > '0'){
		logoutReseller();
        	exit(
        	createJsonMessage(
                	array(
                        	'level' => 'Error',
                        	'message' => sprintf('Cannot add account: %s - You have already used all available Mailaccounts.', $newEmail)
                	)
        	)
        	);


	}
	
	$stmt = exec_query("SELECT SUM(`quota`) AS `quota` FROM `mail_users` WHERE `domain_id` = ? AND quota IS NOT NULL", $domainId);
	$domainCurrentQuota = $stmt->fields['quota'];

	if($domainQuota < $domainCurrentQuota + $quota && $domainQuota > '0'){
		logoutReseller();
        	exit(
        	createJsonMessage(
                	array(
                        	'level' => 'Error',
                        	'message' => sprintf('Cannot add account: %s - Not enough quota left.', $newEmail)
                	)
        	)
        	);


	}


	try {
		$db->beginTransaction();
		iMSCP_Events_Manager::getInstance()->dispatch(
			iMSCP_Events::onBeforeAddMail, 
			array(
				'mailUsername' => $account, 
				'MailAddress' => $newEmail
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
					$account, $newEmailPass, $forwardList, $domainId, $account_type, '0',
					'toadd', '0', NULL, $quota, $newEmail
				)
			);
		$recordId = $db->insertId();

		iMSCP_Events_Manager::getInstance()->dispatch(
			iMSCP_Events::onAfterAddMail,
			array('
				mailUsername' => $account, 
				'mailAddress' => $newEmail, 
				'mailId' => $recordId)
		);
		
		send_request();

		write_log(
			sprintf(
				"%s add Mail: %s (for domain: %s) via remote bridge.",
				decode_idna($auth->getIdentity()->admin_name), $newEmail, $domain
			),
			E_USER_NOTICE
		);

		$db->commit();

	} catch (iMSCP_Exception_Database $e) {
		$db->rollBack();
		echo(
		createJsonMessage(
			array(
				'level' => 'Error',
				'message' => sprintf(
					'Error while creating New Mail: %s, $s, %s', $e->getMessage(), $e->getQuery(), $e->getCode()
				)
			)
		)
		);
		logoutReseller();
		exit;
	}

	echo(
	createJsonMessage(
		array(
			'level' => 'Success',
			'message' => sprintf('New email address %s added successfull.', $newEmail)
		)
	)
	);
}
