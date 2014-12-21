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
 * Create new subdomain
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function addSubDomain($resellerId, $postData)
{
    $db = iMSCP_Registry::get('db');
    $cfg = iMSCP_Registry::get('config');
    $auth = iMSCP_Authentication::getInstance();

    if (empty($postData['domain']) || empty($postData['subdomain'])) {
        logoutReseller();
        exit(
        createJsonMessage(
            array(
                'level' => 'Error',
                'message' => 'No domain or subdomain in post data available.'
            )
        )
        );
    } else {
        $domainType = 'dmn';
        $mountPoint = null;

        $dmnquery = "SELECT `domain_id` FROM `domain` WHERE `domain_name` = ?";

        $stmt = exec_query($dmnquery, $postData['domain']);
        $domainId = $stmt->fields['domain_id'];

        $checkquery = "SELECT `domain_id` FROM `subdomain` WHERE `subdomain_name` = ? AND `domain_id` = ?";
        $stmt2 = exec_query($checkquery, array($postData['subdomain'], $domainId));

        if ($stmt2->rowCount() == 0) {

            $db->commit();

            $subLabelAscii = clean_input(encode_idna(strtolower($postData['subdomain'])));
            $forwardUrl = "no";


            if (in_array($subLabelAscii, array('backups', 'cgi-bin', 'errors', 'logs', 'phptmp'))) {
                $mountPoint = "/sub_$subLabelAscii";
            } else {
                $mountPoint = "/$subLabelAscii";
            }


            iMSCP_Events_Manager::getInstance()->dispatch(
                iMSCP_Events::onBeforeAddSubdomain,
                array(
                    'subdomainName' => $postData['subdomain'],
                    'subdomainType' => $domainType,
                    'parentDomainId' => $domainId,
                    'mountPoint' => $mountPoint,
                    'forwardUrl' => $forwardUrl,
                    'customerId' => $domainId
                )
            );


            $query = "
				INSERT INTO `subdomain` (
					`domain_id`, `subdomain_name`, `subdomain_mount`, `subdomain_url_forward`, `subdomain_status`
				) VALUES (
					?, ?, ?, ?, ?
				)
			";

            exec_query($query, array($domainId, $subLabelAscii, $mountPoint, $forwardUrl, 'toadd'));

            update_reseller_c_props($resellerId);
            $db->commit();


            iMSCP_Events_Manager::getInstance()->dispatch(
                iMSCP_Events::onAfterAddSubdomain,
                array(
                    'subdomainName' => $postData['subdomain'],
                    'subdomainType' => $domainType,
                    'parentDomainId' => $domainId,
                    'mountPoint' => $mountPoint,
                    'forwardUrl' => $forwardUrl,
                    'customerId' => $domainId,
                    'subdomainId' => $db->insertId()
                )
            );

            send_request();
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'state' => 1,
                    'level' => 'Success',
                    'message' => sprintf('Subdomain added.', $postData['subdomain'])
                )
            )
            );
        } else {
            logoutReseller();
            exit(
            createJsonMessage(
                array(
                    'state' => 2,
                    'level' => 'Error',
                    'message' => sprintf('Subdomain %s.%s is in use.', $postData['subdomain'], $postData['domain'])
                )
            )
            );
        }
    }
}


/**
 * Edit subdomain
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function editSubDomain($resellerId, $postData){
    // TODO: Add code to edit subdomain
}

/**
 * Delete subdomain
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function deleteSubDomain($resellerId, $postData){
    // TODO: Add code to delete subdomain
}
