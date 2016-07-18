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
 * Check Record Type
 *
 * @param string $recordType
 * @return bool
 */
function checkRecordType($recordType)
{
    $types = array('A', 'AAAA', 'AFSDB', 'CNAME', 'DNAME', 'DNSKEY', 'DS', 'HINFO', 'ISDN', 'LOC', 'MX', 'NAPTR',
        'NSAP', 'NSEC', 'NSEC3', 'OPT', 'PTR', 'RP', 'RRSIG', 'SIG', 'SPF', 'SRV', 'SSHFP', 'TLSA', 'TXT');

// Here we check the record type
    if (!in_array($recordType, $types)) {
        return FALSE;
    } else {
        return TRUE;
    }
}

/**
 * Validate Record Data
 *
 * @param string $recordType Type od DNS Record
 * @param string $domainData Record Data
 * @param string $domain domain name
 * @param int $ttl TimeToLive
 * @param int $prio Priority
 * @return string $domainData Record Data
 */
function validateRecordData($recordType, $domainData, $domain, $ttl, $prio, $recordName){
    switch($recordType){
        case 'A':
            if (filter_var($domainData, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
		logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'IPv4 in A data is invalid.'
            			)
        		)
        	);
            }
            break;
        case 'AAAA':
            if (filter_var($domainData, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
                logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'IPv6 in AAAA data is invalid.'
            			)
        		)
        	);
            }
            break;
        case 'AFSDB':

            break;
        case 'CNAME':
            if ($domainData == '.') {
                logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'CNAME value is invalid in record_data.'
            			)
        		)
        	);
            }
            if (substr($domainData, -1) == '.') {
                $domainData = rtrim($domainData, '.');
            }
            if (strpos($domainData, '.') === false && $domainData != '@') {
                $domainData .= $domain;
            }
            if ($domainData != '@' && !isValidDomainName($domainData)) {
                logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'Invalid CNAME.'
            			)
        		)
        	);
            }
            break;
        case 'DNAME':

            break;
        case 'DNSKEY':

            break;
        case 'DS':

            break;
        case 'HINFO':

            break;
        case 'ISDN':
            if(!is_numeric($domainData))
            {
                logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => sprintf('This is not a valid ISND number: %s',$domainData)
            			)
        		)
        	);
            }

            break;
        case 'LOC':

            break;
        case 'MX':
            $domainData = (!empty($prio)) ? $prio . ' ' . $domainData : $domainData;
            break;
        case 'NAPTR':

            break;
        case 'NSAP':

            break;
        case 'NSEC':

            break;
        case 'NSEC3':

            break;
        case 'OPT':

            break;
        case 'PTR':
            if (filter_var($recordName, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'IPv4 in record name is invalid.'
            			)
        		)
        	);
            }
            else {
                $recordName = strrev($recordName) . '.in-addr.arpa';
            }
            break;
        case 'RP':

            break;
        case 'RRSIG':

            break;
        case 'SIG':

            break;
        case 'SPF':
            if (!preg_match('/^([a-zA-Z0-9\+\?\-\*_~=:. \/;@])+$/',
                str_replace('"', '', $domainData))) {
                logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'SPF is invalid.'
            			)
        		)
        	);
            }
            break;
        case 'SRV':

            break;
        case 'SSHFP':

            break;
        case 'TLSA':

            break;
        case 'TXT':
            if (!preg_match('/^([a-zA-Z0-9\+\?\-\*_~=:. \/;@])+$/',
                str_replace('"', '', $domainData))) {
                logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'TXT data is invalid.'
            			)
        		)
        	);
            }
            break;
        default:
            logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'Record-Type: '.$recordType.' not implemented yet'
            			)
        		)
        	);
    }
 
    $recordName = (!empty($ttl)) ? $recordName .' '. $ttl : $recordName;
    
    $domainData = (!empty($domainPrio)) ? $domainData .' '. $domainPrio : $domainData;
    	
    return array($domainData, $recordName);
}

/**
 * Create new DNS entry
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function addDnsRecord($resellerId, $postData)
{
    $db = iMSCP_Registry::get('db');

    if (empty($postData['domain']) || empty($postData['record_data']) ||
        empty($postData['record_type'])
    ) {
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'No domain, record_data or record_type in post data available.'
            			)
        		)
        	);
    }

    $domain = (isset($postData['domain'])) ? encode_idna($postData['domain']) : '';
    $domainId = getDomainIdByDomain($domain);
    $domainAdminId = getDomainAdminIdByDomainId($domainId);
    $logUser = (isset($postData['log_user'])) ? clean_input($postData['log_user']) : encode_idna($postData['domain']);
    $recordType = (isset($postData['record_type'])) ? strtoupper(clean_input($postData['record_type'])) : '';
    $recordName = (isset($postData['record_name'])) ? clean_input($postData['record_name']) : '';
    $ttl = (isset($postData['ttl'])) ? intval(clean_input($postData['ttl'])) : 86400;
    $domainClass = (isset($postData['record_class'])) ? strtoupper(clean_input($postData['record_class'])) : 'IN';
    $domainPrio = (isset($postData['record_prio'])) ? intval(clean_input($postData['record_prio'])) : 10;
    $domainData = (isset($postData['record_data'])) ? clean_input($postData['record_data']) : '';
    $domainProperties = get_domain_default_props($domainAdminId);
    $dnsRecordAllow = $domainProperties['domain_dns'];

    // has customer DNS feature
    if ($dnsRecordAllow == 'no') {
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'You are not allowed to use the DNS feature.'
            			)
        		)
        	);
    }

    // check record type
    if (!checkRecordType($recordType)) {
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'Record type is not supported yet'
            			)
        		)
        	);
    }

    list(
        $domainData, $domainDNS
        ) = validateRecordData($recordType, $domainData, $domain, $ttl, $domainPrio, $recordName);

    try {
	$db = iMSCP_Registry::get('db');
        $db->beginTransaction();

        $query = 'INSERT INTO domain_dns(
        		domain_id, alias_id, domain_dns, 
			domain_class, domain_type, domain_text, owned_by, domain_dns_status
        	) VALUES (
        		?, ?, ?, ?, ?, ?, ?, ?
        	)';
	exec_query($query, array($domainId, '0', $domainDNS,
            $domainClass, $recordType, $domainData, 'custom_dns_feature', 'toadd')
	);
        $db->commit();
	write_log(sprintf("%s: added DNS-Record for domain: %s ", $logUser, $domain), E_USER_NOTICE);
        update_reseller_c_props($resellerId);
        send_request();
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Success',
                			'message' => 'New DNS record successfully added.'
            			)
        		)
        	);

    } catch (iMSCP_Exception_Database $e) {
	$db->rollBack();
                if ($e->getCode() == 23000) { // Duplicate entries
                    logoutReseller();
        		exit(
        			createJsonMessage(
            				array(
                				'level' => 'Success',
                				'message' => sprintf('DNS record %s for domain %s already exist. Could not add new DNS record', $domainDNS, $domain)            			)
        			)
        		);
                    return false;
            	}
	}
}

/**
 * Edit DNS entry
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function editDnsRecord($resellerId, $postData)
{
    $db = iMSCP_Registry::get('db');

    if (empty($postData['domain']) || empty($postData['record_data']) ||
        empty($postData['record_type'])
    ) {
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'No domain, record_data or record_type in post data available.'
            			)
        		)
        	);
    }

    $domain = (isset($postData['domain'])) ? encode_idna($postData['domain']) : '';
    $domainId = getDomainIdByDomain($domain);
    $domainAdminId = getDomainAdminIdByDomainId($domainId);
    $logUser = (isset($postData['log_user'])) ? clean_input($postData['log_user']) : encode_idna($postData['domain']);
    $recordType = (isset($postData['record_type'])) ? strtoupper(clean_input($postData['record_type'])) : '';
    $recordName = (isset($postData['record_name'])) ? clean_input($postData['record_name']) : '';
    $ttl = (isset($postData['ttl'])) ? intval(clean_input($postData['ttl'])) : 86400;
    $domainClass = (isset($postData['record_class'])) ? strtoupper(clean_input($postData['record_class'])) : 'IN';
    $domainPrio = (isset($postData['record_prio'])) ? intval(clean_input($postData['record_prio'])) : 10;
    $domainData = (isset($postData['record_data'])) ? clean_input($postData['record_data']) : '';
    $domainProperties = get_domain_default_props($domainAdminId);
    $dnsRecordAllow = $domainProperties['domain_dns'];

    // has customer DNS feature
    if ($dnsRecordAllow == 'no') {
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'You are not allowed to use the DNS feature.'
            			)
        		)
        	);
    }

    // check record type
    if (!checkRecordType($recordType)) {
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'Record type is not supported yet'
            			)
        		)
        	);
    }

    list(
        $domainData, $domainDNS
        ) = validateRecordData($recordType, $domainData, $domain, $ttl, $domainPrio, $recordName);

    try {
	$db = iMSCP_Registry::get('db');
        $db->beginTransaction();

        $query = 'UPDATE domain_dns 
		  SET 
			domain_id = ?, domain_class = ?, domain_dns = ?,
			domain_type = ?, domain_text = ?, 
			owned_by = ?, domain_dns_status = ? 
		  WHERE domain_id = ? AND domain_dns LIKE ?
        	  ';
	$stmt = exec_query($query, array($domainId, $domainClass, $domainDNS,
				 $recordType, $domainData, 'custom_dns_feature', 
				 'tochange', $domainId, $recordName . '%')
	);
	if($stmt->rowCount() != 0){
	        $db->commit();
		write_log(sprintf("%s: updated DNS-Record for domain: %s ", $logUser, $domain), E_USER_NOTICE);
        	update_reseller_c_props($resellerId);
        	send_request();
        	logoutReseller();
        		exit(
        			createJsonMessage(
            				array(
                				'level' => 'Success',
                				'message' => 'DNS record successfully updated.'
            				)
        			)
 			);
	       } else {
			logoutReseller();
        	exit(
        		createJsonMessage(
        			array(
                			'level' => 'Error',
                			'message' => 'Could not update non existing DNS record.'            			)
        		)
        	);
	}

    } catch (iMSCP_Exception_Database $e) {
	$db->rollBack();
        logoutReseller();
        exit(
        	createJsonMessage(
            		array(
                		'level' => 'Error',
                		'message' => sprintf('Could not update DNS record. Error was: %s', $e->getMessage())            			)
        	)
        );
        return false;
        }
}

/**
 * Delete DNS entry
 *
 * @param int $resellerId Reseller unique identifier
 * @param array $postData POST data
 * @return void
 */
function deleteDnsRecord($resellerId, $postData)
{
    $db = iMSCP_Registry::get('db');

    if (empty($postData['domain']) || empty($postData['record_name'])) {
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Error',
                			'message' => 'No domain or record_name in post data available.'
            			)
        		)
        	);
    }

    $domain = (isset($postData['domain'])) ? encode_idna($postData['domain']) : '';
    $domainId = getDomainIdByDomain($domain);
    $logUser = (isset($postData['log_user'])) ? clean_input($postData['log_user']) : encode_idna($postData['domain']);
    $recordName = (isset($postData['record_name'])) ? clean_input($postData['record_name']) : '';

    try {
	$db = iMSCP_Registry::get('db');
        $db->beginTransaction();

        $query = 'UPDATE domain_dns 
		  SET 
			domain_dns_status = ? 
		  WHERE domain_id = ? AND domain_dns LIKE ?
        	 ';
	$stmt = exec_query($query, array('todelete', $domainId, $recordName . '%')
		);
	if($stmt->rowCount() != 0){
        $db->commit();
	write_log(sprintf("%s: deleted DNS-Record for domain: %s ", $logUser, $domain), E_USER_NOTICE);
        update_reseller_c_props($resellerId);
        send_request();
        logoutReseller();
        	exit(
        		createJsonMessage(
            			array(
                			'level' => 'Success',
                			'message' => 'DNS record successfully deleted.'
            			)
        		)
        	);
	} else {
		logoutReseller();
        	exit(
        		createJsonMessage(
        			array(
                			'level' => 'Error',
                			'message' => 'Could not delete non existing DNS record.'            			)
        		)
        	);
	}

    } catch (iMSCP_Exception_Database $e) {
	$db->rollBack();
        logoutReseller();
        exit(
        	createJsonMessage(
        		array(
                		'level' => 'Error',
                		'message' => sprintf('Could not delete DNS record. Error was: %s', $e->getMessage())            			)
        	)
        );
        return false;
	}
}

function getDns($postData)
{
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
    $domain = (isset($postData['domain'])) ? encode_idna($postData['domain']) : '';
    $domainId = getDomainIdByDomain($domain);

    $stmt = exec_query('SELECT domain_dns, domain_class, domain_type, domain_text FROM domain_dns WHERE domain_id = ?',$domainId);

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
