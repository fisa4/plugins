<?php
/**
 * i-MSCP RemoteBridge plugin
 * Copyright (C) 2013-2015 Sascha Bay <info@space2place.de>
 * Copyright (C) 2013-2016 Peter Ziergöbel <info@fisa4.de>
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
 */

return array(
	'up' => '
		CREATE TABLE IF NOT EXISTS `remote_bridge` (
				`bridge_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
				`bridge_admin_id` int(11) unsigned NOT NULL,
				`bridge_ipaddress` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
				`bridge_key` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
				`bridge_status` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
				PRIMARY KEY (`bridge_id`),
				UNIQUE KEY `bridge_api_key` (`bridge_admin_id`, `bridge_ipaddress`),
				KEY `bridge_admin_id` (`bridge_admin_id`)
			) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
	',
	'down' => '
		DROP TABLE IF EXISTS `remote_bridge`
	'
);
