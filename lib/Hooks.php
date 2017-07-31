<?php
/**

 *
 * @author Semih Serhat Karakaya
 * @copyright Copyright (c) 2016, ITU IT HEAD OFFICE.
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

use OCP\IUser;
use OCP\IUserManager;
use OCP\IRequest;

/**
 * Class Hooks
 * @package OCA\Secuity\Lib
 */
class Hooks {

    /** @var \OC\User\Manager */
    private $userManager;

    /** @var Throttle*/
    private $throttle;

    /** @var IRequest*/
    private $request;

    /**
     * @param IUserManager $userManager
     * @param Throttle $throttle
     * @param IRequest
     */
    public function __construct($userManager, $throttle, $request){
        $this->userManager = $userManager;
        $this->throttle = $throttle;
        $this->request = $request;
    }

    public function register() {
        $this->userManager->listen('\OC\User', 'failedLogin', function($uid) {
            $this->failedLoginCallback($uid);
        });

        $this->userManager->listen('\OC\User', 'postLogin', function($user) {
            $this->postLoginCallback($user);
        });
    }

    /**
     * @param string $uid
     * @param Throttle $throttle
     */
    public function failedLoginCallback($uid) {
        $this->throttle->addFailedLoginAttempt($uid, $this->request->getRemoteAddress());
        $this->throttle->putDelay($uid, $this->request->getRemoteAddress());
    }

    /**
     * @param IUser $user
     */
    public function postLoginCallback($user) {
        $this->throttle->clearSuspiciousAttemptsForIp($this->request->getRemoteAddress());
    }
}
