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

namespace OCA\Security;

use OC\HintException;
use OCP\IL10N;

class PasswordValidator  {

	/** @var SecurityConfig */
	protected $config;

	/** @var IL10N */
	protected $l;

	/**
	 * PasswordValidator constructor.
	 *
	 * @param SecurityConfig $config
	 * @param IL10N $l
	 */
	public function __construct(SecurityConfig $config, IL10N $l) {
		$this->config = $config;
		$this->l = $l;
	}

	/**
	 * validate the given password satisfies defined password policy
	 *
	 * @param string $password
	 * @throws HintException
	 */
	public function validate($password) {
		$this->checkPasswordLength($password);
		$this->checkNumericCharacters($password);
		$this->checkUpperLowerCase($password);
		$this->checkSpecialCharacters($password);
	}

	/**
	 * validate the given password satisfies defined min length
	 *
	 * @param string $password
	 * @throws HintException
	 */
	public function checkPasswordLength($password) {
		$minPassLength = $this->config->getMinPasswordLength();
		if(strlen($password) < $minPassLength) {
			$message = 'Password needs to be at least ' . $minPassLength . ' characters long';
			$hint = $this->l->t(
				'Password needs to be at least %s characters long', [$minPassLength]
			);
			throw new HintException($message, $hint);
		}
	}

	/**
	 * validate if password contains at least one upper and one lower case character
	 *
	 * @param string $password
	 * @throws HintException
	 */
	public function checkUpperLowerCase($password) {
		$enforceUpperLowerCase= $this->config->getIsUpperLowerCaseEnforced();
		if($enforceUpperLowerCase === true && $this->hasUpperAndLowerCase($password) === false) {
			$message = 'Password should contain at least one upper and one lower case character.';
			$hint = $this->l->t(
				'Password should contain at least one upper and one lower case character.'
			);
			throw new HintException($message, $hint);
		}
	}

	/**
	 * validate the given password satisfies numeric character policy
	 *
	 * @param string $password
	 * @throws HintException
	 */
	public function checkNumericCharacters($password) {
		$enforceNumericCharacters = $this->config->getIsNumericCharactersEnforced();
		if($enforceNumericCharacters === true && $this->hasNumericalCharacters($password) === false) {
			$message = 'Password should contain at least one numerical character.';
			$hint = $this->l->t(
				'Password should contain at least one numerical character.'
			);
			throw new HintException($message, $hint);
		}
	}

	/**
	 * check if password contains at least one special character
	 *
	 * @param string $password
	 * @throws HintException
	 */
	public function checkSpecialCharacters($password) {
		$enforceSpecialCharacters = $this->config->getIsSpecialCharactersEnforced();
		if($enforceSpecialCharacters === true && $this->hasSpecialCharacter($password) === false) {
			$message = 'Password should contain at least one special character.';
			$hint = $this->l->t(
				'Password should contain at least one special character.'
			);
			throw new HintException($message, $hint);
		}
	}

	public function hasNumericalCharacters($password) {
		return preg_match('/\d/', $password) === 1 ? true : false;
	}

	public function hasUpperAndLowerCase($password) {
		$toLower = strtolower($password);
		$toUpper = strtoupper($password);
		return ($toLower !== $password && $toUpper !== $password) ? true : false;
	}

	public function hasSpecialCharacter($password) {
		return (!ctype_alnum($password));
	}
}