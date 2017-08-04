<?php
/**
 * @author Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
namespace OCA\Security\Tests\Controller;

use OCA\Security\Controller\SettingsController;
use OCA\Security\SecurityConfig;
use OCP\IRequest;
use Test\TestCase;

class SettingsControllerTest extends TestCase {
	/** @var IRequest|\PHPUnit_Framework_MockObject_MockObject */
	private $request;
	/** @var SecurityConfig|\PHPUnit_Framework_MockObject_MockObject */
	private $config;
	/** @var SettingsController */
	private $controller;
	protected function setUp() {
		parent::setUp();
		$this->request = $this->getMockBuilder(IRequest::class)->getMock();
		$this->config = $this->getMockBuilder(SecurityConfig::class)
			->disableOriginalConstructor()
			->getMock();
		$this->controller = new SettingsController('security', $this->request, $this->config);
	}
	public function testState() {
		$expected = [
			'bruteForceProtectionState' => true,
			'minPassLength' => 8,
			'enforceUpperLowerState' => true,
			'enforceNumericalCharactersState' => true,
			'enforceSpecialCharactersState' => true
		];
		$this->config->expects($this->exactly(1))
			->method('getAllSecurityConfigs')
			->willReturn($expected);

		$this->assertEquals($expected, $this->controller->state());
	}
}