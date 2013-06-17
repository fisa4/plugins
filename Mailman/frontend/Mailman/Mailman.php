<?php
/**
 * i-MSCP - internet Multi Server Control Panel
 * Copyright (C) 2010-2013 by i-MSCP Team
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
 * @subpackage  Mailman
 * @copyright   2010-2013 by i-MSCP Team
 * @author      Laurent Declercq <l.declercq@nuxwin.com>
 * @link        http://www.i-mscp.net i-MSCP Home Site
 * @license     http://www.gnu.org/licenses/gpl-2.0.html GPL v2
 */

/**
 * Mailman Plugin.
 *
 * @category    iMSCP
 * @package     iMSCP_Plugin
 * @subpackage  Mailman
 * @author      Laurent Declercq <l.declercq@nuxwin.com>
 */
class iMSCP_Plugin_Mailman extends iMSCP_Plugin_Action
{
	/**
	 * @var array
	 */
	protected $routes = array();

	/**
	 * Process plugin installation
	 *
	 * @param iMSCP_Plugin_Manager $pluginManager
	 */
	public function install($pluginManager)
	{
		$db = iMSCP_Database::getInstance();

		try {
			$db->beginTransaction();
			$this->addDbTable();
			$db->commit();
		} catch(iMSCP_Exception $e) {
			$db->rollBack();
			$pluginManager->setStatus($this->getName(), $e->getMessage());
		}

		$pluginManager->setStatus($this->getName(), 'enabled');
	}

	/**
	 * Process plugin un-installation
	 *
	 * @return void
	 */
	public function _uninstall()
	{
		// Un-installation tasks are delegated to the engine - Just send backend request
		send_request();
	}

	/**
	 * Register a callback for the given event(s).
	 *
	 * @param iMSCP_Events_Manager_Interface $controller
	 */
	public function register(iMSCP_Events_Manager_Interface $controller)
	{
		$controller->registerListener(iMSCP_Events::onClientScriptStart, $this);

		$this->routes = array(
			'/client/mailman.php' => PLUGINS_PATH . '/' . $this->getName() . '/client/mailman.php'
		);
	}

	/**
	 * Implements the onClientScriptStart event
	 *
	 * @return void
	 */
	public function onClientScriptStart()
	{
		$this->injectMailmanLinks();

		if(isset($_REQUEST['plugin']) && $_REQUEST['plugin'] == 'mailman') {
			$this->handleRequest();
		}
	}

	/**
	 * Get routes
	 *
	 * @return array
	 */
	public function getRoutes()
	{
		return $this->routes;
	}

	/**
	 * Inject Mailman links into the navigation object
	 */
	protected function injectMailmanLinks()
	{
		if (iMSCP_Registry::isRegistered('navigation')) {
			/** @var Zend_Navigation $navigation */
			$navigation = iMSCP_Registry::get('navigation');

			if (($page = $navigation->findOneBy('uri', '/client/mail_accounts.php'))) {
				$page->addPage(
					array(
						'label' => tohtml(tr('E-Mail Lists')),
						'uri' => '/client/mailman.php',
						'title_class' => 'plugin'
					)
				);
			}
		}
	}

	/**
	 * Handle Mailman plugin requests
	 */
	protected function handleRequest()
	{
		if(isset($_REQUEST['plugin']) && $_REQUEST['plugin'] == 'mailman') {
			// Load mailman action script
			require_once PLUGINS_PATH . '/Mailman/admin/mailman.php';
			exit;
		}
	}

	/**
	 * Add mailman database table
	 *
	 * @return void
	 */
	protected function addDbTable()
	{
		$query = "
			CREATE TABLE IF NOT EXISTS `mailman` (
  				`mailman_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  				`mailman_admin_id` int(11) unsigned NOT NULL,
  				`mailman_admin_email` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  				`mailman_admin_password` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  				`mailman_listname` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  				`mailman_status` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
  				PRIMARY KEY (`mailman_id`),
  				KEY `mailman_admin_id` (`mailman_admin_id`)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci AUTO_INCREMENT=1 ;
		";

		execute_query($query);
	}
}