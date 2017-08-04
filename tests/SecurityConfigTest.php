<?php
/**
 * @copyright Copyright (c) 2017 Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
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
namespace OCA\Security\Tests;

use OCA\Security\SecurityConfig;
use OCP\IConfig;
use Test\TestCase;
class SecurityConfigTest extends TestCase {
	/** @var  IConfig|\PHPUnit_Framework_MockObject_MockObject */
	private $config;
	/** @var  SecurityConfig */
	private $securityConfig;
	public function setUp() {
		parent::setUp();
		$this->config = $this->createMock(IConfig::class);
		$this->securityConfig = new SecurityConfig($this->config);
	}

	/**
	 * @param array $mockedMethods
	 * @return SecurityConfig | \PHPUnit_Framework_MockObject_MockObject
	 */
	private function getMockInstance($mockedMethods = []) {
		$passwordValidator = $this->getMockBuilder('OCA\Security\SecurityConfig')
			->setConstructorArgs([$this->config])
			->setMethods($mockedMethods)->getMock();
		return $passwordValidator;
	}

	public function testGetAllSecurityConfigs() {
		$instance = $this->getMockInstance(
			[
				'getIsBruteForceProtectionEnabled',
				'getMinPasswordLength',
				'getIsUpperLowerCaseEnforced',
				'getIsNumericCharactersEnforced',
				'getIsSpecialCharactersEnforced'
			]
		);
		$instance->expects($this->once())->method('getIsBruteForceProtectionEnabled');
		$instance->expects($this->once())->method('getMinPasswordLength');
		$instance->expects($this->once())->method('getIsUpperLowerCaseEnforced');
		$instance->expects($this->once())->method('getIsNumericCharactersEnforced');
		$instance->expects($this->once())->method('getIsNumericCharactersEnforced');
		$instance->getAllSecurityConfigs();
	}
	/**
	 * @dataProvider configTestData
	 * @param string $appConfigValue
	 * @param bool $expected
	 */
	public function testGetIsBruteForceProtectionEnabled($appConfigValue, $expected) {
		$this->config->expects($this->once())->method('getAppValue')
			->with('security', 'enable_brute_force_protection', '0')
			->willReturn($appConfigValue);
		$this->assertSame($expected,
			$this->securityConfig->getIsBruteForceProtectionEnabled()
		);
	}
	/**
	 * @dataProvider minPassTestData
	 * @param string $appConfigValue
	 * @param bool $expected
	 */
	public function testGetMinPasswordLength($appConfigValue, $expected) {
		$this->config->expects($this->once())->method('getAppValue')
			->with('security', 'min_password_length', '8')
			->willReturn($appConfigValue);
		$this->assertSame($expected,
			$this->securityConfig->getMinPasswordLength()
		);
	}
	/**
	 * @dataProvider configTestData
	 * @param string $appConfigValue
	 * @param bool $expected
	 */
	public function testGetIsUpperLowerCaseEnforced($appConfigValue, $expected) {
		$this->config->expects($this->once())->method('getAppValue')
			->with('security', 'enforce_upper_lower_case', '0')
			->willReturn($appConfigValue);
		$this->assertSame($expected,
			$this->securityConfig->getIsUpperLowerCaseEnforced()
		);
	}
	/**
	 * @dataProvider configTestData
	 * @param string $appConfigValue
	 * @param bool $expected
	 */
	public function testGetIsNumericCharactersEnforced($appConfigValue, $expected) {
		$this->config->expects($this->once())->method('getAppValue')
			->with('security', 'enforce_numeric_characters', '0')
			->willReturn($appConfigValue);
		$this->assertSame($expected,
			$this->securityConfig->getIsNumericCharactersEnforced()
		);
	}
	/**
	 * @dataProvider configTestData
	 * @param string $appConfigValue
	 * @param bool $expected
	 */
	public function testGetIsSpecialCharactersEnforced($appConfigValue, $expected) {
		$this->config->expects($this->once())->method('getAppValue')
			->with('security', 'enforce_special_characters', '0')
			->willReturn($appConfigValue);
		$this->assertSame($expected,
			$this->securityConfig->getIsSpecialCharactersEnforced()
		);
	}
	/**
	 * @dataProvider configTestData
	 * @param string $expected
	 * @param bool $setValue
	 */
	public function testSetIsBruteForceProtectionEnabled($expected, $setValue) {
		$this->config->expects($this->once())->method('setAppValue')
			->with('security', 'enable_brute_force_protection', $expected);
		$this->securityConfig->setIsBruteForceProtectionEnabled($setValue);
	}
	/**
	 * @dataProvider minPassTestData
	 * @param string $expected
	 * @param bool $setValue
	 */
	public function testSetMinPasswordLength($expected, $setValue) {
		$this->config->expects($this->once())->method('setAppValue')
			->with('security', 'min_password_length', $expected);
		$this->securityConfig->setMinPasswordLength($setValue);
	}
	/**
	 * @dataProvider configTestData
	 * @param string $expected
	 * @param bool $setValue
	 */
	public function testSetIsUpperLowerCaseEnforced($expected, $setValue) {
		$this->config->expects($this->once())->method('setAppValue')
			->with('security', 'enforce_upper_lower_case', $expected);
		$this->securityConfig->setIsUpperLowerCaseEnforced($setValue);
	}
	/**
	 * @dataProvider configTestData
	 * @param string $expected
	 * @param bool $setValue
	 */
	public function testSetIsNumericCharactersEnforced($expected, $setValue) {
		$this->config->expects($this->once())->method('setAppValue')
			->with('security', 'enforce_numeric_characters', $expected);
		$this->securityConfig->setIsNumericCharactersEnforced($setValue);
	}
	/**
	 * @dataProvider configTestData
	 * @param string $expected
	 * @param bool $setValue
	 */
	public function testSetIsSpecialCharactersEnforced($expected, $setValue) {
		$this->config->expects($this->once())->method('setAppValue')
			->with('security', 'enforce_special_characters', $expected);
		$this->securityConfig->setIsSpecialCharactersEnforced($setValue);
	}
	public function configTestData() {
		return [
			['1', true],
			['0', false],
		];
	}
	public function minPassTestData() {
		return [
			['8', 8],
			['16', 16],
			['255', 255]
		];
	}
}