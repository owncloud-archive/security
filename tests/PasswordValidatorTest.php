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
namespace OCA\Password_Policy\Tests;
use OC\HintException;
use OCA\Security\SecurityConfig;
use OCA\Security\PasswordValidator;
use OCP\IL10N;
use Test\TestCase;
class PasswordValidatorTest extends TestCase {

	/** @var  SecurityConfig|\PHPUnit_Framework_MockObject_MockObject */
	private $config;

	/** @var  IL10N|\PHPUnit_Framework_MockObject_MockObject */
	private $l10n;

	/** @var  PasswordValidator */
	private $passValidator;

	public function setUp() {
		parent::setUp();
		$this->l10n = $this->createMock(IL10N::class);
		$this->config = $this->createMock(SecurityConfig::class);
		$this->passValidator = new PasswordValidator($this->config, $this->l10n);
	}

	/**
	 * @param array $mockedMethods
	 * @return PasswordValidator | \PHPUnit_Framework_MockObject_MockObject
	 */
	private function getMockInstance($mockedMethods = []) {
		$passwordValidator = $this->getMockBuilder('OCA\Security\PasswordValidator')
			->setConstructorArgs([$this->config, $this->l10n])
			->setMethods($mockedMethods)->getMock();
		return $passwordValidator;
	}

	public function testCheckPasswordLength() {
		$this->config->expects($this->exactly(1))->method('getMinPasswordLength')->willReturn(4);
		$this->passValidator->checkPasswordLength('password');
	}
	/**
	 * @expectedException \OC\HintException
	 */
	public function testCheckPasswordLengthFail() {
		$this->config->expects($this->exactly(1))->method('getMinPasswordLength')->willReturn(4);
		$this->passValidator->checkPasswordLength('123');
	}
	/**
	 * @dataProvider dataTestCheckUpperLowerCase
	 *
	 * @param string $password
	 * @param bool $enforceUpperLowerCase
	 */
	public function testCheckUpperLowerCase($password, $enforceUpperLowerCase) {
		$this->config->expects($this->once())->method('getIsUpperLowerCaseEnforced')
			->willReturn($enforceUpperLowerCase);
		$this->passValidator->checkUpperLowerCase($password);
	}
	public function dataTestCheckUpperLowerCase() {
		return [
			['testPass', true],
			['Testpass', true],
			['testpass', false],
			['TESTPASS', false],
		];
	}
	/**
	 * @dataProvider dataTestCheckUpperLowerCaseFail
	 * @param string $password
	 * @expectedException \OC\HintException
	 */
	public function testCheckUpperLowerCaseFail($password) {
		$this->config->expects($this->once())->method('getIsUpperLowerCaseEnforced')->willReturn(true);
		$this->passValidator->checkUpperLowerCase($password);
	}
	public function dataTestCheckUpperLowerCaseFail() {
		return [
			['TESTPASS'], ['testpass']
		];
	}
	/**
	 * @dataProvider dataTestCheckNumericCharacters
	 *
	 * @param string $password
	 * @param bool $enforceNumericCharacters
	 */
	public function testCheckNumericCharacters($password, $enforceNumericCharacters) {
		$this->config->expects($this->once())->method('getIsNumericCharactersEnforced')->willReturn($enforceNumericCharacters);
		$this->passValidator->checkNumericCharacters($password);
	}
	public function dataTestCheckNumericCharacters() {
		return [
			['testPass1', true],
			['testpass', false]
		];
	}
	/**
	 * @dataProvider dataTestCheckNumericCharactersFail
	 * @param string $password
	 * @expectedException \OC\HintException
	 */
	public function testCheckNumericCharactersFail($password) {
		$this->config->expects($this->once())->method('getIsNumericCharactersEnforced')->willReturn(true);
		$this->passValidator->checkNumericCharacters($password);
	}
	public function dataTestCheckNumericCharactersFail() {
		return [
			['testpass'],
			['TestPass%'],
			['TEST*PASS']
		];
	}
	/**
	 * @dataProvider dataTestCheckSpecialCharacters
	 *
	 * @param string $password
	 * @param bool $enforceSpecialCharacters
	 */
	public function testCheckSpecialCharacters($password, $enforceSpecialCharacters) {
		$this->config->expects($this->once())->method('getIsSpecialCharactersEnforced')->willReturn($enforceSpecialCharacters);
		$this->passValidator->checkSpecialCharacters($password);
	}
	public function dataTestCheckSpecialCharacters() {
		return [
			['testPass%', true],
			['testpass', false]
		];
	}
	/**
	 * @dataProvider dataTestCheckSpecialCharactersFail
	 * @param string $password
	 * @expectedException \OC\HintException
	 */
	public function testCheckSpecialCharactersFail($password) {
		$this->config->expects($this->once())->method('getIsSpecialCharactersEnforced')->willReturn(true);
		$this->passValidator->checkSpecialCharacters($password);
	}
	public function dataTestCheckSpecialCharactersFail() {
		return [
			['testpass'],
			['TestPass1'],
			['TEST2PASS']
		];
	}
	public function testValidate() {
		$password = 'password';
		$instance = $this->getMockInstance(
			[
				'checkPasswordLength',
				'checkUpperLowerCase',
				'checkNumericCharacters',
				'checkSpecialCharacters',
			]
		);
		$instance->expects($this->once())->method('checkPasswordLength')->with($password);
		$instance->expects($this->once())->method('checkUpperLowerCase')->with($password);
		$instance->expects($this->once())->method('checkNumericCharacters')->with($password);
		$instance->expects($this->once())->method('checkSpecialCharacters')->with($password);
		$instance->validate($password);
	}
}