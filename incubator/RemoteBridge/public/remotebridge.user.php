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
 * @author	Thom Heemstra <thom@heemstra.us>
 * 
 * @link        http://www.i-mscp.net i-MSCP Home Site
 * @license     http://www.gnu.org/licenses/gpl-2.0.html GPL v2
 */

/**
 * Create new user
 *
 * @param int $resellerId Reseller unique identifier
 * @param string $resellerHostingPlan Hosting plan name
 * @param string $resellerIpaddress IP address
 * @param array $postData POST data
 * @return void
 */
function createNewUser($resellerId, $resellerHostingPlan, $resellerIpaddress, $postData)
{
	$db = iMSCP_Registry::get('db');
	$cfg = iMSCP_Registry::get('config');
	$auth = iMSCP_Authentication::getInstance();

	if (empty($postData['domain']) || empty($postData['admin_pass']) || empty($postData['email'])) {
		logoutReseller();
		exit(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => 'No domain, user password, or user email address in post data available.'
				)
			)
		);
	}

	remoteBridgecheckPasswordSyntax($postData['admin_pass']);

	$domain = strtolower($postData['domain']);
	$dmnUsername = encode_idna($postData['domain']);

	if (!isValidDomainName($dmnUsername)) {
		logoutReseller();
		exit(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => sprintf('The domain %s is not valid.', $domain)
				)
			)
		);
	}

	if (imscp_domain_exists($dmnUsername, $resellerId)) {
		logoutReseller();
		exit(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => sprintf('Domain %s already exist on this server.', $domain)
				)
			)
		);
	}

	$pure_user_pass = urldecode($postData['admin_pass']);
	$admin_pass = cryptPasswordWithSalt($pure_user_pass);
	$fname = (isset($postData['fname'])) ? clean_input(urldecode($postData['fname'])) : '';
	$lname = (isset($postData['lname'])) ? clean_input(urldecode($postData['lname'])) : '';
	$firm = (isset($postData['firm'])) ? clean_input(urldecode($postData['firm'])) : '';
	$zip = (isset($postData['zip'])) ? clean_input(urldecode($postData['zip'])) : '';
	$city = (isset($postData['city'])) ? clean_input(urldecode($postData['city'])) : '';
	$state = (isset($postData['state'])) ? clean_input(urldecode($postData['state'])) : '';
	$country = (isset($postData['country'])) ? clean_input(urldecode($postData['country'])) : '';
	$userEmail = (isset($postData['email'])) ? clean_input(urldecode($postData['email'])) : '';
	$phone = (isset($postData['phone'])) ? clean_input(urldecode($postData['phone'])) : '';
	$fax = (isset($postData['fax'])) ? clean_input(urldecode($postData['fax'])) : '';
	$street1 = (isset($postData['street1'])) ? clean_input(urldecode($postData['street1'])) : '';
	$street2 = (isset($postData['street2'])) ? clean_input(urldecode($postData['street2'])) : '';
	$customer_id = (isset($postData['customer_id'])) ? clean_input(urldecode($postData['customer_id'])) : '';
	$gender = (
		(isset($postData['gender']) && $postData['gender'] == 'M') ||
		(isset($postData['gender']) && $postData['gender'] == 'F')
	) ? clean_input(urldecode($postData['gender'])) : 'U';

	try {
		$db->beginTransaction();

		$query = "
			INSERT INTO `admin` (
				`admin_name`, `admin_pass`, `admin_type`, `domain_created`, `created_by`, `fname`, `lname`, `firm`,
				`zip`, `city`, `state`, `country`, `email`, `phone`, `fax`, `street1`, `street2`, `customer_id`,
				`gender`, `admin_status`
			) VALUES (
				?, ?, 'user', unix_timestamp(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			)
		";
		exec_query(
			$query,
			array(
				$dmnUsername, $admin_pass, $resellerId, $fname, $lname, $firm, $zip, $city, $state, $country,
				$userEmail, $phone, $fax, $street1, $street2, $customer_id, $gender, $cfg->ITEM_TOADD_STATUS
			)
		);

		$recordId = $db->insertId();

		iMSCP_Events_Manager::getInstance()->dispatch(
			iMSCP_Events::onBeforeAddDomain,
			array(
				'domainName' => $dmnUsername,
				'createdBy' => $resellerId,
				'customerId' => $recordId,
				'customerEmail' => $userEmail
			)
		);

		if (count($resellerHostingPlan) == 0) {
			$mailQuota = ($postData['mail_quota'] != '0') ? $postData['mail_quota'] * 1048576 : '0';
		} else {
			$mailQuota = ($resellerHostingPlan['mail_quota'] != '0') ? $resellerHostingPlan['mail_quota'] * 1048576 : '0';
		}

		$dmnExpire = 0;
		$domain_mailacc_limit = (count($resellerHostingPlan) == 0)
			? $postData['hp_mail'] : $resellerHostingPlan['hp_mail'];
		$domain_mail_quota = $mailQuota;
		$domain_ftpacc_limit = (count($resellerHostingPlan) == 0)
			? $postData['hp_ftp'] : $resellerHostingPlan['hp_ftp'];
		$domain_traffic_limit = (count($resellerHostingPlan) == 0)
			? $postData['hp_traff'] : $resellerHostingPlan['hp_traff'];
		$domain_sqld_limit = (count($resellerHostingPlan) == 0)
			? $postData['hp_sql_db'] : $resellerHostingPlan['hp_sql_db'];
		$domain_sqlu_limit = (count($resellerHostingPlan) == 0)
			? $postData['hp_sql_user'] : $resellerHostingPlan['hp_sql_user'];
		$domain_subd_limit = (count($resellerHostingPlan) == 0) ? $postData['hp_sub'] : $resellerHostingPlan['hp_sub'];
		$domain_alias_limit = (count($resellerHostingPlan) == 0) ? $postData['hp_als'] : $resellerHostingPlan['hp_als'];
		$domain_ip_id = $resellerIpaddress;
		$domain_disk_limit = (count($resellerHostingPlan) == 0)
			? $postData['hp_disk'] : $resellerHostingPlan['hp_disk'];
		$domain_php = (count($resellerHostingPlan) == 0)
			? $postData['hp_php'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_php']);
		$domain_cgi = (count($resellerHostingPlan) == 0)
			? $postData['hp_cgi'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_cgi']);
		$allowbackup = (count($resellerHostingPlan) == 0)
			? $postData['hp_backup'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_backup']);
		$domain_dns = (count($resellerHostingPlan) == 0)
			? $postData['hp_dns'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_dns']);
		$domain_software_allowed = (count($resellerHostingPlan) == 0)
			? $postData['hp_allowsoftware'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_allowsoftware']);
		$phpini_perm_system = (count($resellerHostingPlan) == 0)
			? $postData['phpini_system'] : $resellerHostingPlan['phpini_system'];
		$phpini_perm_allow_url_fopen = (count($resellerHostingPlan) == 0)
			? $postData['phpini_perm_allow_url_fopen'] : $resellerHostingPlan['phpini_perm_allow_url_fopen'];
		$phpini_perm_display_errors = (count($resellerHostingPlan) == 0)
			? $postData['phpini_perm_display_errors'] : $resellerHostingPlan['phpini_perm_display_errors'];
		$phpini_perm_disable_functions = (count($resellerHostingPlan) == 0)
			? $postData['phpini_perm_disable_functions'] : $resellerHostingPlan['phpini_perm_disable_functions'];
		$domain_external_mail = (count($resellerHostingPlan) == 0)
			? $postData['external_mail'] : preg_replace("/\_/", '', $resellerHostingPlan['external_mail']);
		$webFolderProtection = (count($resellerHostingPlan) == 0)
			? $postData['web_folder_protection']
			: preg_replace("/\_/", '', $resellerHostingPlan['web_folder_protection']);

		$query = "
			INSERT INTO `domain` (
				`domain_name`, `domain_admin_id`, `domain_created`, `domain_expires`,
				`domain_mailacc_limit`, `domain_ftpacc_limit`, `domain_traffic_limit`, `domain_sqld_limit`,
				`domain_sqlu_limit`, `domain_status`, `domain_subd_limit`, `domain_alias_limit`, `domain_ip_id`,
				`domain_disk_limit`, `domain_disk_usage`, `domain_php`, `domain_cgi`, `allowbackup`, `domain_dns`,
				`domain_software_allowed`, `phpini_perm_system`, `phpini_perm_allow_url_fopen`,
				`phpini_perm_display_errors`, `phpini_perm_disable_functions`, `domain_external_mail`,
				`web_folder_protection`, `mail_quota`
			) VALUES (
				?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
			)
		";

		exec_query(
			$query,
			array(
				$dmnUsername, $recordId, time(), $dmnExpire, $domain_mailacc_limit, $domain_ftpacc_limit,
				$domain_traffic_limit, $domain_sqld_limit, $domain_sqlu_limit, $cfg->ITEM_TOADD_STATUS,
				$domain_subd_limit, $domain_alias_limit, $domain_ip_id, $domain_disk_limit, 0, $domain_php, $domain_cgi,
				$allowbackup, $domain_dns, $domain_software_allowed, $phpini_perm_system, $phpini_perm_allow_url_fopen,
				$phpini_perm_display_errors, $phpini_perm_disable_functions, $domain_external_mail,
				$webFolderProtection, $domain_mail_quota
			)
		);

		$dmnId = $db->insertId();

		if ($phpini_perm_system == 'yes') {
			$phpini = iMSCP_PHPini::getInstance();

			$phpini->setData('phpiniSystem', 'yes');
			$phpini->setData('phpiniPostMaxSize', (count($resellerHostingPlan) == 0)
				? $postData['phpini_post_max_size'] : $resellerHostingPlan['phpini_post_max_size']);
			$phpini->setData('phpiniUploadMaxFileSize', (count($resellerHostingPlan) == 0)
				? $postData['phpini_upload_max_filesize'] : $resellerHostingPlan['phpini_upload_max_filesize']);
			$phpini->setData('phpiniMaxExecutionTime', (count($resellerHostingPlan) == 0)
				? $postData['phpini_max_execution_time'] : $resellerHostingPlan['phpini_max_execution_time']);
			$phpini->setData('phpiniMaxInputTime', (count($resellerHostingPlan) == 0)
				? $postData['phpini_max_input_time'] : $resellerHostingPlan['phpini_max_input_time']);
			$phpini->setData('phpiniMemoryLimit', (count($resellerHostingPlan) == 0)
				? $postData['phpini_memory_limit'] : $resellerHostingPlan['phpini_memory_limit']);

			$phpini->saveCustomPHPiniIntoDb($dmnId);
		}

		$query = "INSERT INTO `htaccess_users` (`dmn_id`, `uname`, `upass`, `status`) VALUES (?, ?, ?, ?)";
		exec_query($query, array($dmnId, $dmnUsername, cryptPasswordWithSalt($pure_user_pass), $cfg->ITEM_TOADD_STATUS));

		$user_id = $db->insertId();

		$query = 'INSERT INTO `htaccess_groups` (`dmn_id`, `ugroup`, `members`, `status`) VALUES (?, ?, ?, ?)';
		exec_query($query, array($dmnId, $cfg->WEBSTATS_GROUP_AUTH, $user_id, $cfg->ITEM_TOADD_STATUS));

		// Create default addresses if needed
		if ($cfg->CREATE_DEFAULT_EMAIL_ADDRESSES) {
			client_mail_add_default_accounts($dmnId, $userEmail, $dmnUsername);
		}

		$query = "INSERT INTO `user_gui_props` (`user_id`, `lang`, `layout`) VALUES (?, ?, ?)";
		exec_query($query, array($recordId, $cfg->USER_INITIAL_LANG, $cfg->USER_INITIAL_THEME));

		update_reseller_c_props($resellerId);

		$db->commit();

		iMSCP_Events_Manager::getInstance()->dispatch(
			iMSCP_Events::onAfterAddDomain,
			array(
				'domainName' => $dmnUsername,
				'createdBy' => $resellerId,
				'customerId' => $recordId,
				'customerEmail' => $userEmail,
				'domainId' => $dmnId
			)
		);
		
                send_add_user_auto_msg($resellerId, $dmnUsername, $pure_user_pass, $fname, $lname, "Customer"); // Needs i10n/i18n

		send_request();

		write_log(
			sprintf(
				"%s add user: " . $domain . " (for domain " . $domain . ") via remote bridge",
				decode_idna($auth->getIdentity()->admin_name)
			),
			E_USER_NOTICE
		);
		write_log(
			sprintf(
				"%s add user: add domain: " . $domain . " via remote bridge",
				decode_idna($auth->getIdentity()->admin_name)
			),
			E_USER_NOTICE
		);

	} catch (iMSCP_Exception_Database $e) {
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

	if (isset($postData['alias_domains']) && count($postData['alias_domains']) > 0) {
		createAliasDomain($resellerId, $dmnId, $domain_ip_id, $postData);
	}

	echo(
		createJsonMessage(
			array(
				'level' => 'Success',
				'message' => sprintf('User %s added successfull.', $domain)
			)
		)
	);
}

/**
 * Delete user
 *
 * @param int $resellerId Reseller unique identifier
 * @param string $domain Customer main domain name
 * @return void
 */
function deleteUser($resellerId, $domain)
{
	//$db = iMSCP_Registry::get('db');
	//$cfg = iMSCP_Registry::get('config');

	$auth = iMSCP_Authentication::getInstance();

	$dmnUsername = encode_idna($domain);

	$query = '
		SELECT
			domain_admin_id, domain_status, created_by
		FROM
			domain
		INNER JOIN
			admin ON(admin_id = domain_admin_id)
		WHERE
			domain_name = ?
	';
	$stmt = exec_query($query, $dmnUsername);

	if ($stmt->rowCount() && $stmt->fields['created_by'] == $resellerId) {
		$customerId = $stmt->fields['domain_admin_id'];
		try {
			if (!deleteCustomer($customerId, true)) {
				logoutReseller();
				exit(
					createJsonMessage(
						array(
							'level' => 'Error',
							'message' => sprintf('Customer account %s not found.', $domain)
						)
					)
				);
			}
			echo(
				createJsonMessage(
					array(
						'level' => 'Success',
						'message' => sprintf('Customer account: %s successfully scheduled for deletion.', $domain)
					)
				)
			);
			write_log(
				sprintf('%s scheduled deletion of the customer account: %s',
					decode_idna($auth->getIdentity()->admin_name), $domain
				),
				E_USER_NOTICE
			);
			send_request();
		} catch (iMSCP_Exception $e) {
			write_log(
				sprintf(
					'System was unable to schedule deletion of the customer account: %s. Message was: %s',
					$domain,
					$e->getMessage()
				),
				E_USER_ERROR
			);

			logoutReseller();
			exit(
				createJsonMessage(
					array(
						'level' => 'Error',
						'message' => sprintf(
							'System was unable to schedule deletion of the customer account: %s.', $domain
						)
					)
				)
			);
		}
	} else {
		echo(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => sprintf('Unknown domain %s.', $domain)
				)
			)
		);
	}
}

/**
 * Disable user
 *
 * @param int $resellerId Reseller unique identifier
 * @param string $domain Customer main domain name
 * @return void
 */
function disableUser($resellerId, $domain)
{
	//$db = iMSCP_Registry::get('db');
	$cfg = iMSCP_Registry::get('config');
	$auth = iMSCP_Authentication::getInstance();

	$dmnUsername = encode_idna($domain);

	$query = '
		SELECT
			domain_admin_id, domain_status, created_by
		FROM
			domain
		INNER JOIN
			admin ON(admin_id = domain_admin_id)
		WHERE
			domain_name = ?
	';
	$stmt = exec_query($query, $dmnUsername);

	if ($stmt->rowCount() && $stmt->fields['created_by'] == $resellerId) {
		$customerId = $stmt->fields['domain_admin_id'];

		if ($stmt->fields['domain_status'] == $cfg->ITEM_OK_STATUS) {
			change_domain_status($customerId, 'deactivate');
			send_request();
			write_log(
				sprintf(
					'%s disabled the customer account: %s via remote bridge',
					decode_idna($auth->getIdentity()->admin_name),
					$domain
				),
				E_USER_NOTICE
			);
			echo(
				createJsonMessage(
					array(
						'level' => 'Success',
						'message' => sprintf('Domain %s succesfully disabled.', $domain)
					)
				)
			);
		} else {
			echo(
				createJsonMessage(
					array(
						'level' => 'Error',
						'message' => sprintf(
							'Cannot disable domain %s. Current domain status is: %s.',
							$domain,
							$stmt->fields['domain_status']
						)
					)
				)
			);
		}
	} else {
		echo(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => sprintf('Unknown domain %s.', $domain)
				)
			)
		);
	}
}

/**
 * Enable user
 *
 * @param int $resellerId Reseller unique identifier
 * @param string $domain Customer main domain name
 * @return void
 */
function enableUser($resellerId, $domain)
{
	//$db = iMSCP_Registry::get('db');
	$cfg = iMSCP_Registry::get('config');
	$auth = iMSCP_Authentication::getInstance();

	$dmnUsername = encode_idna($domain);

	$query = '
		SELECT
			domain_admin_id, domain_status, created_by
		FROM
			domain
		INNER JOIN
			admin ON(admin_id = domain_admin_id)
		WHERE
			domain_name = ?
	';
	$stmt = exec_query($query, $dmnUsername);

	if ($stmt->rowCount() && $stmt->fields['created_by'] == $resellerId) {
		$customerId = $stmt->fields['domain_admin_id'];

		if ($stmt->fields['domain_status'] == $cfg->ITEM_DISABLED_STATUS) {
			change_domain_status($customerId, 'activate');
			send_request();
			write_log(
				sprintf(
					'%s activated the customer account: %s via remote bridge',
					decode_idna($auth->getIdentity()->admin_name),
					$domain
				),
				E_USER_NOTICE
			);

			echo(
				createJsonMessage(
					array(
						'level' => 'Success',
						'message' => sprintf('Domain %s succesfully activated.', $domain)
					)
				)
			);
		} else {
			echo(
				createJsonMessage(
					array(
						'level' => 'Error',
						'message' => sprintf(
							'Cannot activate domain %s. Current domain status is: %s.',
							$domain, $stmt->fields['domain_status']
						)
					)
				)
			);
		}
	} else {
		echo(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => sprintf('Unknown domain %s.', $domain)
				)
			)
		);
	}
}

/**
 * Collect usage data
 *
 * @param int $resellerId Reseller unique identifier
 * @param string $domain Customer main domain name
 * @return void
 */
function collectUsageData($resellerId, $domain)
{
	$query = '
		SELECT
			domain_id
		FROM
			domain
		INNER JOIN
			admin ON(admin_id = domain_admin_id)
		WHERE
			created_by = ?
	';

	if ($domain == 'all') {
		$stmt = exec_query($query, $resellerId);
	} else {
		$query .= ' AND domain_name = ?';
		$dmnUsername = encode_idna($domain);
		$stmt = exec_query($query, array($resellerId, $dmnUsername));
	}

	if (!$stmt->rowCount()) {
		exit(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => ($domain === 'all')
						? sprintf('No usage data available.') : sprintf('Unknown domain %s.', $domain)
				)
			)
		);
	} else {
		$usageData = array();

		foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $domainId) {
			list(
				$domainName, $domainId, , , , , $trafficUsageBytes, $diskspaceUsageBytes
				) = generate_user_traffic($domainId);

			list(
				$usub_current, $usub_max, $uals_current, $uals_max, $umail_current, $umail_max, $uftp_current, $uftp_max,
				$usql_db_current, $usql_db_max, $usql_user_current, $usql_user_max, $trafficLimit, $diskspaceLimit
				) = generate_user_props($domainId);

			if ($domainName != 'n/a') {
				$usageData[$domainName] = array(
					'domain' => $domainName,
					'disk_used' => $diskspaceUsageBytes,
					'disk_limit' => $diskspaceLimit * 1048576,
					'bw_used' => $trafficUsageBytes,
					'bw_limit' => $trafficLimit * 1048576,
					'subdomain_used' => $usub_current,
					'subdomain_limit' => $usub_max,
					'alias_used' => $uals_current,
					'alias_limit' => $uals_max,
					'mail_used' => $umail_current,
					'mail_limit' => $umail_max,
					'ftp_used' => $uftp_current,
					'ftp_limit' => $uftp_max,
					'sqldb_used' => $usql_db_current,
					'sqldb_limit' => $usql_db_max,
					'sqluser_used' => $usql_user_current,
					'sqluser_limit' => $usql_user_max
				);
			} else {
				exit(
					createJsonMessage(
						array(
							'level' => 'Error',
							'message' => sprintf('Error while collecting usage statistics for domain %s.', $domain)
						)
					)
				);
			}
		}

		echo(
			createJsonMessage(
				array(
					'level' => 'Success',
					'message' => sprintf('Usage statistics for domain %s successfully generated.', $domain),
					'data' => $usageData
				)
			)
		);
	}
}

/**
 * Create user list
 *
 * @param $resellerId
 * @return user list 
 */

function getUserList($resellerId)
{
	$query = '
		SELECT
			admin_name
		FROM
			admin
		WHERE
			created_by = ?
	';

	$stmt = exec_query($query, $resellerId);
	
	if ( !$stmt->rowCount() ) {
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
				'message' => sprintf('User list successfully generated.'),
				'data' => $result
			)
		)
	);
}

/**
* Update user
*
* @param int $resellerId Reseller unique identifier
* @param string $resellerHostingPlan HostingPlan name
* @param string $resellerIpaddress IP address
* @param array $postData POST data
* @return void
*/
function updateUser($resellerId, $resellerHostingPlan, $resellerIpaddress, $postData)
{
	$db = iMSCP_Registry::get('db');
	$cfg = iMSCP_Registry::get('config');
	$auth = iMSCP_Authentication::getInstance();

	if (empty($postData['domain'])) {
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
	if(! empty($postData['admin_pass'])){
		remoteBridgecheckPasswordSyntax($postData['admin_pass']);
		$pure_user_pass = urldecode($postData['admin_pass']);
		$admin_pass = cryptPasswordWithSalt($pure_user_pass);
	}

	$domain = strtolower($postData['domain']);
	$dmnUsername = encode_idna($postData['domain']);

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
			domain_id
		FROM
			domain
		WHERE
			domain_name = ?
	';
	$stmt = exec_query($query, $domain);
	$domainId = $stmt->fields['domain_id'];

	try {
		$db->beginTransaction();

		iMSCP_Events_Manager::getInstance()->dispatch(
			iMSCP_Events::onBeforeEditDomain,
			array(
				'domainName' => $dmnUsername,
				'createdBy' => $resellerId,
				'customerId' => $recordId,
				'customerEmail' => $userEmail
			)
		);

	$dmnExpire = 0;
	$domain_mailacc_limit = (count($resellerHostingPlan) == 0)
		? $postData['hp_mail'] : $resellerHostingPlan['hp_mail'];
	$domain_mail_quota = $mailQuota;
	$domain_ftpacc_limit = (count($resellerHostingPlan) == 0)
		? $postData['hp_ftp'] : $resellerHostingPlan['hp_ftp'];
	$domain_traffic_limit = (count($resellerHostingPlan) == 0)
		? $postData['hp_traff'] : $resellerHostingPlan['hp_traff'];
	$domain_sqld_limit = (count($resellerHostingPlan) == 0)
		? $postData['hp_sql_db'] : $resellerHostingPlan['hp_sql_db'];
	$domain_sqlu_limit = (count($resellerHostingPlan) == 0)
		? $postData['hp_sql_user'] : $resellerHostingPlan['hp_sql_user'];
	$domain_subd_limit = (count($resellerHostingPlan) == 0) 
		? $postData['hp_sub'] : $resellerHostingPlan['hp_sub'];
	$domain_alias_limit = (count($resellerHostingPlan) == 0) 
		? $postData['hp_als'] : $resellerHostingPlan['hp_als'];
	$domain_ip_id = $resellerIpaddress;
	$domain_disk_limit = (count($resellerHostingPlan) == 0)
		? $postData['hp_disk'] : $resellerHostingPlan['hp_disk'];
	$domain_php = (count($resellerHostingPlan) == 0)
		? $postData['hp_php'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_php']);
	$domain_cgi = (count($resellerHostingPlan) == 0)
		? $postData['hp_cgi'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_cgi']);
	$allowbackup = (count($resellerHostingPlan) == 0)
		? $postData['hp_backup'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_backup']);
	$domain_dns = (count($resellerHostingPlan) == 0)
		? $postData['hp_dns'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_dns']);
	$domain_software_allowed = (count($resellerHostingPlan) == 0)
		? $postData['hp_allowsoftware'] : preg_replace("/\_/", '', $resellerHostingPlan['hp_allowsoftware']);
	$phpini_perm_system = (count($resellerHostingPlan) == 0)
		? $postData['phpini_system'] : $resellerHostingPlan['phpini_system'];
	$phpini_perm_allow_url_fopen = (count($resellerHostingPlan) == 0)
		? $postData['phpini_perm_allow_url_fopen'] : $resellerHostingPlan['phpini_perm_allow_url_fopen'];
	$phpini_perm_display_errors = (count($resellerHostingPlan) == 0)
		? $postData['phpini_perm_display_errors'] : $resellerHostingPlan['phpini_perm_display_errors'];
	$phpini_perm_disable_functions = (count($resellerHostingPlan) == 0)
		? $postData['phpini_perm_disable_functions'] : $resellerHostingPlan['phpini_perm_disable_functions'];
	$domain_external_mail = (count($resellerHostingPlan) == 0)
		? $postData['external_mail'] : preg_replace("/\_/", '', $resellerHostingPlan['external_mail']);
	$webFolderProtection = (count($resellerHostingPlan) == 0)
		? $postData['web_folder_protection']
		: preg_replace("/\_/", '', $resellerHostingPlan['web_folder_protection']);

	$query = "
		UPDATE
			`domain`
		SET
			`domain_expires` = ?, `domain_last_modified` = ?, `domain_mailacc_limit` = ?,
			`domain_ftpacc_limit` = ?, `domain_traffic_limit` = ?, `domain_sqld_limit` = ?,
			`domain_sqlu_limit` = ?, `domain_status` = ?, `domain_alias_limit` = ?, `domain_subd_limit` = ?,
			`domain_ip_id` = ?, `domain_disk_limit` = ?, `domain_php` = ?, `domain_cgi` = ?, `allowbackup` = ?,
			`domain_dns` = ?,  `domain_software_allowed` = ?, `phpini_perm_system` = ?,
			`phpini_perm_allow_url_fopen` = ?, `phpini_perm_display_errors` = ?,
			`phpini_perm_disable_functions` = ?, `domain_external_mail` = ?, `web_folder_protection` = ?,
			`mail_quota` = ?
		WHERE
			`domain_id` = ?
			";
	exec_query(
		$query,
		array(
			$dmnExpire, time(), $domain_mailacc_limit, 
			$domain_ftpacc_limit, $domain_traffic_limit, $domain_sqld_limit, 
			$domain_sqlu_limit, $cfg->ITEM_TOCHANGE_STATUS,	$domain_alias_limit, $domain_subd_limit, 
			$domain_ip_id, $domain_disk_limit, $domain_php, $domain_cgi, $allowbackup, 
			$domain_dns, $domain_software_allowed, $phpini_perm_system, 
			$phpini_perm_allow_url_fopen, $phpini_perm_display_errors, 
			$phpini_perm_disable_functions, $domain_external_mail,	$webFolderProtection, 
			$domain_mail_quota, $domainId
		)
	);

	$dmnId = $db->insertId();

	if ($phpini_perm_system == 'yes') {
		$phpini = iMSCP_PHPini::getInstance();
		$phpini->setData('phpiniSystem', 'yes');
		$phpini->setData('phpiniPostMaxSize', (count($resellerHostingPlan) == 0)
			? $postData['phpini_post_max_size'] : $resellerHostingPlan['phpini_post_max_size']);
		$phpini->setData('phpiniUploadMaxFileSize', (count($resellerHostingPlan) == 0)
			? $postData['phpini_upload_max_filesize'] : $resellerHostingPlan['phpini_upload_max_filesize']);
		$phpini->setData('phpiniMaxExecutionTime', (count($resellerHostingPlan) == 0)
			? $postData['phpini_max_execution_time'] : $resellerHostingPlan['phpini_max_execution_time']);
		$phpini->setData('phpiniMaxInputTime', (count($resellerHostingPlan) == 0)
			? $postData['phpini_max_input_time'] : $resellerHostingPlan['phpini_max_input_time']);
		$phpini->setData('phpiniMemoryLimit', (count($resellerHostingPlan) == 0)
			? $postData['phpini_memory_limit'] : $resellerHostingPlan['phpini_memory_limit']);
		$phpini->saveCustomPHPiniIntoDb($dmnId);
	}

	update_reseller_c_props($resellerId);

	$db->commit();

	iMSCP_Events_Manager::getInstance()->dispatch(
		iMSCP_Events::onAfterEditDomain,
		array(
			'domainName' => $dmnUsername,
			'createdBy' => $resellerId,
			'customerId' => $recordId,
			'customerEmail' => $userEmail,
			'domainId' => $dmnId
		)
	);

	send_request();

	write_log(
		sprintf(
			"%s update user: " . $domain . " (for domain " . $domain . ") via remote bridge",
			decode_idna($auth->getIdentity()->admin_name)
		),
		E_USER_NOTICE
	);
	write_log(
		sprintf(
			"%s update user: update domain: " . $domain . " via remote bridge",
			decode_idna($auth->getIdentity()->admin_name)
		),
		E_USER_NOTICE
	);

	}
	catch (iMSCP_Exception_Database $e) {
		$db->rollBack();
		logoutReseller();
		exit(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => sprintf(
						'Error while updating user: %s, $s, %s', $e->getMessage(), $e->getQuery(), $e->getCode()
					)
				)
			)
		);
	}

	echo(
		createJsonMessage(
			array(
				'level' => 'Success',
				'message' => sprintf('User %s update successful.', $domain)
			)
		)
	);
}
