<?php
/**
 * @author Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
 * @copyright Copyright (c) 2017, ownCloud GmbH.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

namespace OCA\Security\Panels;

use OCA\Security\SecurityConfig;
use OCP\Settings\ISettings;
use OCP\Template;

class PersonalPanel implements ISettings {

	/** @var SecurityConfig */
	private $config;

	public function __construct(SecurityConfig $config) {
		$this->config = $config;
	}

	public function getPanel() {
		$params = $this->config->getAllSecurityConfigs();
		$tmpl = new Template('security', 'settings-personal');
		foreach ($params as $key => $value) {
			$tmpl->assign($key, $value);
		}
		return $tmpl;
	}

	public function getSectionID() {
		return 'general';
	}

	public function getPriority() {
		return 0;
	}
}