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

use OCP\IConfig;
/**
 * Class Config
 *
 * read/write config of the security policies
 *
 * @package OCA\Security
 */
class SecurityConfig {

    /** @var IConfig */
    private $config;

    /**
     * Config constructor.
     *
     * @param IConfig $config
     */
    public function __construct(IConfig $config) {
        $this->config = $config;
    }

    /**
     * is brute force protection enabled
     *
     * @return array
     */
    public function getAllSecurityConfigs() {
        return [
            'bruteForceProtectionFailTolerance' => $this->getBruteForceProtectionFailTolerance(),
            'bruteForceProtectionTimeThreshold' => $this->getBruteForceProtectionTimeThreshold(),
            'bruteForceProtectionBanPeriod' => $this->getBruteForceProtectionBanPeriod(),
            'minPasswordLength' => $this->getMinPasswordLength(),
            'isUpperLowerCaseEnforced' => $this->getIsUpperLowerCaseEnforced(),
            'isNumericalCharsEnforced' => $this->getIsNumericCharactersEnforced(),
            'isSpecialCharsEnforced' => $this->getIsSpecialCharactersEnforced()
        ];
    }

    /**
     * ban after how many failed attempts
     *
     * @return int
     */
    public function getBruteForceProtectionFailTolerance() {
        $tolerance = $this->config->getAppValue(
            'security',
            'brute_force_protection_fail_tolerance',
            '3'
        );
        return intval($tolerance);
    }

    /**
     * Count failed login attempts over how many seconds
     *
     * @return int
     */
    public function getBruteForceProtectionTimeThreshold() {
        $timeThreshold = $this->config->getAppValue(
            'security',
            'brute_force_protection_time_threshold',
            '600'
        );
        return intval($timeThreshold);
    }

    /**
     * How many seconds to ban an attacker
     *
     * @return int
     */
    public function getBruteForceProtectionBanPeriod() {
        $banPeriod = $this->config->getAppValue(
            'security',
            'brute_force_protection_ban_period',
            '300'
        );
        return intval($banPeriod);
    }

    /**
     * get the enforced minimum length of passwords
     *
     * @return int
     */
    public function getMinPasswordLength() {
        $minLength = $this->config->getAppValue('security', 'min_password_length', '8');
        return intval($minLength);
    }
    /**
     * does the password need to contain upper and lower case characters
     *
     * @return bool
     */
    public function getIsUpperLowerCaseEnforced() {
        $enforceUpperLowerCase = $this->config->getAppValue(
            'security',
            'enforce_upper_lower_case',
            '0'
        );
        return boolval($enforceUpperLowerCase);
    }
    /**
     * does the password need to contain numeric characters
     *
     * @return bool
     */
    public function getIsNumericCharactersEnforced() {
        $enforceNumericCharacters = $this->config->getAppValue(
            'security',
            'enforce_numeric_characters',
            '0'
        );
        return boolval($enforceNumericCharacters);
    }
    /**
     * does the password need to contain special characters
     *
     * @return bool
     */
    public function getIsSpecialCharactersEnforced() {
        $enforceSpecialCharacters = $this->config->getAppValue(
            'security',
            'enforce_special_characters',
            '0'
        );
        return boolval($enforceSpecialCharacters);
    }
    /*
     * @param int $attempts
     */
    public function setBruteForceProtectionFailTolerance($attempts) {
        $this->config->setAppValue('security', 'brute_force_protection_fail_tolerance', $attempts);
    }
    /**
     * @param int $seconds
     */
    public function setBruteForceProtectionTimeThreshold($seconds) {
        $this->config->setAppValue('security', 'brute_force_protection_time_threshold', $seconds);
    }
    /**
     * @param int $seconds
     */
    public function setBruteForceProtectionBanPeriod($seconds) {
        $this->config->setAppValue('security', 'brute_force_protection_ban_period', $seconds);
    }
    /**
     * set minimal length of passwords
     *
     * @param int $minLength
     */
    public function setMinPasswordLength($minLength) {
        $this->config->setAppValue('security', 'min_password_length', $minLength);
    }
    /**
     * enforce upper and lower characters case
     *
     * @param bool $enforceUpperLowerCase
     */
    public function setIsUpperLowerCaseEnforced($enforceUpperLowerCase) {
        $value = $enforceUpperLowerCase === true ? '1' : '0';
        $this->config->setAppValue('security', 'enforce_upper_lower_case', $value);
    }
    /**
     * enforce numeric characters
     *
     * @param bool $enforceNumericCharacters
     */
    public function setIsNumericCharactersEnforced($enforceNumericCharacters) {
        $value = $enforceNumericCharacters === true ? '1' : '0';
        $this->config->setAppValue('security', 'enforce_numeric_characters', $value);
    }
    /**
     * enforce special characters
     *
     * @param bool $enforceSpecialCharacters
     */
    public function setIsSpecialCharactersEnforced($enforceSpecialCharacters) {
        $value = $enforceSpecialCharacters === true ? '1' : '0';
        $this->config->setAppValue('security', 'enforce_special_characters', $value);
    }
}