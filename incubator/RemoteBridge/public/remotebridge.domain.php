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
* Update domain
*
* @param int $resellerId Reseller unique identifier
* @param string $resellerHostingPlan HostingPlan name
* @param string $resellerIpaddress IP address
* @param array $postData POST data
* @return void
*/
function updateDomain($resellerId, $resellerHostingPlan, $resellerIpaddress, $postData)
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
			$dmnExpire, $lastModified, $domain_mailacc_limit, 
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
		echo(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => sprintf(
						'Error while updating user: %s, $s, %s', $e->getMessage(), $e->getQuery(), $e->getCode()
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
			'message' => sprintf('User %s update successfull.', $domain)
			)
		)
	);
}
