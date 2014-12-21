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

include_once('remotebridge.core.php');
include_once('remotebridge.user.php');
include_once('remotebridge.alias.php');
include_once('remotebridge.mail.php');
include_once('remotebridge.database.php');
include_once('remotebridge.dns.php');
include_once('remotebridge.domain.php');
include_once('remotebridge.ftp.php');

$filter = iMSCP_Registry::set(
	'bufferFilter',
	new iMSCP_Filter_Compress_Gzip(iMSCP_Filter_Compress_Gzip::FILTER_BUFFER)
);
$filter->compressionInformation = false;
ob_start(array($filter, iMSCP_Filter_Compress_Gzip::CALLBACK_NAME));

checkRemoteIpaddress($_SERVER['REMOTE_ADDR']);

if (isset($_POST['key']) && isset($_POST['data'])) {
	checkiMSCP_Version();

	$postData = decryptPostData($_POST['key'], $_SERVER['REMOTE_ADDR'], $_POST['data']);
	$resellerId = checkResellerLoginData($postData['reseller_username'], $postData['reseller_password']);
	$action = isset($postData['action']) ? $postData['action'] : 'default';

	switch ($action) {
		case 'get_users':
			getUserList($resellerId);

			break;
		case 'create': // Deprecated action name since 0.0.5
		case 'create_user':
			$resellerHostingPlan = (isset($postData['hosting_plan']))
				? checkResellerHostingPlan($resellerId, $postData['hosting_plan']) : array();

			$resellerIpaddress = checkResellerAssignedIP($resellerId);

			if (count($resellerHostingPlan) == 0) {
				checkLimitsPostData($postData, $resellerId);
			}

			createNewUser($resellerId, $resellerHostingPlan, $resellerIpaddress, $postData);

			break;
		case 'unsuspend': // Deprecated action name since 0.0.5
		case 'enable_user':
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

			enableUser($resellerId, $postData['domain']);

			break;
		case 'suspend': // Deprecated action name since 0.0.5
		case 'disable_user':
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

			disableUser($resellerId, $postData['domain']);

			break;
		case 'terminate': // Deprecated action name since 0.0.5
		case 'delete_user':
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

			deleteUser($resellerId, $postData['domain']);

			break;
		case 'update_user':
			 $resellerHostingPlan = (isset($postData['hosting_plan']))
					? checkResellerHostingPlan($resellerId, $postData['hosting_plan']) : array();

			$resellerIpaddress = checkResellerAssignedIP($resellerId);

			if (count($resellerHostingPlan) == 0) {
					checkLimitsPostData($postData, $resellerId);
			}

			updateUser($resellerId, $resellerHostingPlan, $resellerIpaddress, $postData);

			break; 
		case 'add_alias':
			$resellerIpaddress = checkResellerAssignedIP($resellerId);
			addAliasDomain($resellerId, $resellerIpaddress, $postData);
			break;
		case 'get_mails':
			if (empty($postData['domain'])) {
				logoutReseller();
				exit(
					createJsonMessage(
						array(
							'level' => 'Error',
							'message' => 'No reseller name in post data available.'
						)
					)
				);
			}

			getMailList($resellerId, $postData['domain']);

			break;
		case 'add_mail':
			addMailAccount($resellerId, $postData);

			break;
		case 'check_mail':
			checkMail($postData);

			break;
		case 'delete_mail':
			deleteMail($resellerId, $postData);

			break;
		case 'add_subdomain':
			addSubDomain($resellerId, $postData)

			break;
		case 'check_subdomain':


			break;
		case 'collectusagedata':
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

			collectUsageData($resellerId, $postData['domain']);

			break;
		default:
			exit(
				createJsonMessage(
					array(
						'level' => 'Error',
						'message' => sprintf('This action: %s is not implemented.', $action)
					)
				)
			);
	}

	logoutReseller();

	exit;
}

exit(
createJsonMessage(
	array(
		'level' => 'Error',
		'message' => 'Direct access to remote bridge not allowed.'
	)
)
);
