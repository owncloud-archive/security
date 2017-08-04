<?php
/**
 * @author Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
 *
 * Two-factor Backup Codes
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
 *
 */

namespace OCA\Security\Controller;

use OCA\Security\SecurityConfig;
use OCP\AppFramework\Controller;
use OCP\IRequest;

class SettingsController extends Controller {

	/** @var SecurityConfig */
	private $config;

	/**
	 * @param string $appName
	 * @param IRequest $request
	 * @param SecurityConfig $config
	 */
	public function __construct($appName, IRequest $request, SecurityConfig $config) {
		parent::__construct($appName, $request);
		$this->config = $config;
	}

	/**
	 * @return array
	 */
	public function state() {
		return $this->config->getAllSecurityConfigs();
	}
}
