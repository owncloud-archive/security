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

use OCP\IDBConnection;

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
     * @param IDBConnection $dbConnection
     */
    public function __construct($dbConnection) {
        $this->dbConnection = $dbConnection;
    }

    /**
     * @param string $uid
     * @param string ip
     * @return void
     */
    public function addFailedLoginAttempt($uid, $ip) {
        $this->dbConnection->addFailedLoginAttempt($uid, $ip);
    }

    /**
     * @param string $uid
     * @param string ip
     * @return void
     */
    public function putDelay($uid, $ip) {
        //we determine appropriate delay time by using ip and username info
        //initially it return count of failed attempts for ip
        sleep($this->calculateDelayForIp($ip));
    }

    /**
     * @param string $uid
     * @return int
     */
    public function calculateDelayForUid($uid) {
        return $this->dbConnection->getSuspiciousActivityCountForUid($uid);
    }

    /**
     * @param string ip
     * @return int
     */
    public function calculateDelayForIp($ip) {
        return $this->dbConnection->getSuspiciousActivityCountForIp($ip);
    }

    /**
     * @param string ip
     * @return void
     */
    public function clearSuspiciousAttemptsForIp($ip) {
        $this->dbConnection->deleteSuspiciousAttemptsForIp($ip);
    }
}