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
 * @author      Ninos Ego <me@ninosego.de>
 * @link        http://www.i-mscp.net i-MSCP Home Site
 * @license     http://www.gnu.org/licenses/gpl-2.0.html GPL v2
 */

/**
 * Add domain alias
 *
 * @param int $resellerId Reseller unique identifier
 * @param string $resellerIpaddress IP Address
 * @param array $postData POST data
 * @return void
 */
function addAliasDomain($resellerId, $resellerIpaddress, $postData)
{
	//$db = iMSCP_Registry::get('db');
	//$cfg = iMSCP_Registry::get('config');
	//$auth = iMSCP_Authentication::getInstance();

	if (empty($postData['domain']) || count($postData['alias_domains']) == 0) {
		logoutReseller();
		exit(
			createJsonMessage(
				array(
					'level' => 'Error',
					'message' => 'No domain or domain aliases in post data available.'
				)
			)
		);
	}

	$domain = strtolower($postData['domain']);
	$dmnUsername = encode_idna($postData['domain']);

	$query = '
		SELECT
			domain_admin_id, domain_status, created_by
		FROM
			domain
		INNER JOIN
			admin ON(admin_id = domain_admin_id)
		WHERE
			domain_name= ?
	';
	$stmt = exec_query($query, $dmnUsername);

	if ($stmt->rowCount() && $stmt->fields['created_by'] == $resellerId) {
		$customerId = $stmt->fields['domain_admin_id'];
		createAliasDomain($resellerId, $customerId, $resellerIpaddress, $postData);
		echo(
			createJsonMessage(
				array(
					'level' => 'Success',
					'message' => sprintf(
						'Domain aliases: %s succesfully added.',
						implode(', ', $postData['alias_domains'])
					)
				)
			)
		);
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
 * Create domain alias
 *
 * @param int $resellerId Reseller unique identifier
 * @param int $customerDmnId Customer domain unique identifier
 * @param int $domain_ip_id Domain IP unique identifier
 * @param array $postData POST data
 * @return void
 */
function createAliasDomain($resellerId, $customerDmnId, $domain_ip_id, $postData)
{
	$db = iMSCP_Registry::get('db');
	$cfg = iMSCP_Registry::get('config');
	$auth = iMSCP_Authentication::getInstance();

	foreach ($postData['alias_domains'] as $aliasdomain) {
		$aliasdomain = strtolower($aliasdomain);
		$alias_domain = encode_idna($aliasdomain);

		if (!isValidDomainName(decode_idna($alias_domain))) {
			logoutReseller();
			exit(
				createJsonMessage(
					array(
						'level' => 'Error',
						'message' => sprintf('The alias domain %s is not valid.', $aliasdomain)
					)
				)
			);
		}

		if (imscp_domain_exists($alias_domain, $resellerId)) {
			logoutReseller();
			exit(
				createJsonMessage(
					array(
						'level' => 'Error',
						'message' => sprintf('Alias domain %s already exist on this server.', $aliasdomain)
					)
				)
			);
		}

		$mountPoint = array_encode_idna(strtolower(trim(clean_input($aliasdomain))), true);

		try {
			$db->beginTransaction();

			$customerId = who_owns_this($customerDmnId, 'dmn_id');

			$query = "
				INSERT INTO `domain_aliasses` (
					`domain_id`, `alias_name`, `alias_mount`, `alias_status`, `alias_ip_id`
				) VALUES (
					?, ?, ?, ?, ?
				)
			";
			exec_query($query, array($customerDmnId, $alias_domain, $mountPoint, $cfg->ITEM_TOADD_STATUS, $domain_ip_id));

			$alsId = $db->insertId();

			// Since the reseller is allowed to add an alias for customer accounts, whatever the value of
			// their domain aliases limit, we update the related fields to avoid any consistency problems.

			$customerProps = get_domain_default_props($customerId);
			$newCustomerAlsLimit = 0;

			if ($customerProps['domain_alias_limit'] > 0) { // Customer has als limit
				$query = 'SELECT COUNT(`alias_id`) AS `cnt` FROM `domain_aliasses` WHERE `domain_id` = ?';
				$stmt = exec_query($query, $customerDmnId);
				$customerAlsCount = $stmt->fields['cnt'];

				// If the customer als limit is reached, we extend it
				if ($customerAlsCount >= $customerProps['domain_alias_limit']) {
					$newCustomerAlsLimit += $customerAlsCount;
				}
			} elseif ($customerProps['domain_alias_limit'] != 0) { // Als feature is disabled for the customer.
				// We simply enable als feature by setting the limit to 1
				$newCustomerAlsLimit = 1;

				// We also update reseller current als count (number of assigned als) by incrementing the current value.
				$query = "
					UPDATE
						`reseller_props`
					SET
						`current_als_cnt` = (`current_als_cnt` + 1)
					WHERE
						`reseller_id` = ?
				";
				exec_query($query, $_SESSION['user_id']);
			}

			// We update the customer als limit according if needed
			if ($newCustomerAlsLimit) {
				exec_query(
					"UPDATE `domain` SET `domain_alias_limit` = ? WHERE `domain_admin_id` = ?",
					array($newCustomerAlsLimit, $customerId)
				);
			}

			$query = "SELECT `email` FROM `admin` WHERE `admin_id` = ? LIMIT 1";
			$stmt = exec_query($query, $customerId);
			$customerEmail = $stmt->fields['email'];

			// Create default email accounts if needed
			if ($cfg->CREATE_DEFAULT_EMAIL_ADDRESSES) {
				client_mail_add_default_accounts($customerDmnId, $customerEmail, $alias_domain, 'alias', $alsId);
			}

			$db->commit();

		} catch (iMSCP_Exception_Database $e) {
			$db->rollBack();
			logoutReseller();
			exit(
				createJsonMessage(
					array(
						'level' => 'Error',
						'message' => sprintf(
							'Error while creating alias domain: %s, %s, %s',
							$e->getMessage(),
							$e->getQuery(),
							$e->getCode()
						)
					)
				)
			);
		}

		send_request();
		write_log(
			sprintf(
				'%s added domain alias: %s via remote bridge',
				decode_idna($auth->getIdentity()->admin_name),
				$aliasdomain
			),
			E_USER_NOTICE
		);
	}
}
