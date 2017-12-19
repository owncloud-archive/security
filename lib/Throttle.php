<?php
/**
 * @author Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
 *
 * @copyright Copyright (c) 2017, ownCloud GmbH
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
 *
 */

namespace OCA\Security;

use OC\User\LoginException;
use OCA\Security\Db\DbService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * Class Throttle
 * @package OCA\Secuity\Lib
 */
class Throttle {

    /**
     * @var \OCA\Security\Db\DbService $connection
     */
    protected $dbConnection;

    /**
     * @var SecurityConfig $config
     */
    protected $config;

    /**
     * @var IL10N $l
     */
    protected $l;

    /**
     * @var ITimeFactory $timeFactory
     */
    protected $timeFactory;

    /**
     * @param \OCA\Security\Db\DbService $dbConnection
     * @param SecurityConfig $config
     * @param IL10N $l
     * @param ITimeFactory $timeFactory
     */
    public function __construct(DbService $dbConnection, SecurityConfig $config, IL10N $l, ITimeFactory $timeFactory) {
        $this->dbConnection = $dbConnection;
        $this->config = $config;
        $this->l = $l;
        $this->timeFactory = $timeFactory;
    }

    /**
     * @param string $uid
     * @param string $ip
     * @return void
     */
    public function addFailedLoginAttempt($uid, $ip) {
        $this->dbConnection->addFailedLoginAttempt($uid, $ip);
    }

    /**
     * @param string $uid
     * @param string $ip
     * @throws LoginException
     */
    public function applyBruteForcePolicy($uid ,$ip) {
        $banPeriod = $this->config->getBruteForceProtectionBanPeriod();
        $banUntil = $this->dbConnection->getLastFailedLoginAttemptTimeForIp($ip)+$banPeriod;
        if($this->dbConnection->getSuspiciousActivityCountForUidIpCombination($uid, $ip) >=
            $this->config->getBruteForceProtectionFailTolerance() &&
            $banUntil > $this->timeFactory->getTime()) {
            throw new LoginException($this->l->t("Too many failed login attempts. Try again in %s minutes.",
                ceil($banPeriod/60))
            );
        }
    }

    /**
     * @param string $ip
     * @return void
     */
    public function clearSuspiciousAttemptsForIp($ip) {
        $this->dbConnection->deleteSuspiciousAttemptsForIp($ip);
    }
}