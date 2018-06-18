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

use OC\User\LoginException;
use OCP\IUserManager;
use OCP\IRequest;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\GenericEvent;

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

    /** @var PasswordValidator */
    private $passValidator;

    /** @var EventDispatcherInterface */
    private $dispatcher;

    /**
     * @param IUserManager $userManager
     * @param Throttle $throttle
     * @param IRequest $request
     * @param PasswordValidator $passValidator
     * @param EventDispatcherInterface $dispatcher
     */
    public function __construct($userManager, $throttle, $request, $passValidator, $dispatcher){
        $this->userManager = $userManager;
        $this->throttle = $throttle;
        $this->request = $request;
        $this->passValidator = $passValidator;
        $this->dispatcher = $dispatcher;

    }

    public function register() {
        $this->userManager->listen('\OC\User', 'preLogin', function($uid) {
            $this->preLoginCallback($uid);
        });

        $this->userManager->listen('\OC\User', 'failedLogin', function($uid) {
            $this->failedLoginCallback($uid);
        });
        
        $this->userManager->listen('\OC\User', 'postLogin', function($user) {
            /** @var $user \OC\User\User */
            $this->postLoginCallback($user->getUID());
        });

        $this->dispatcher->addListener('OCP\User::validatePassword', function(GenericEvent $event) {
            $this->passValidator->validate($event->getArgument('password'));
        });

        $this->dispatcher->addListener('OCP\Share::validatePassword', function(GenericEvent $event) {
            $this->passValidator->validate($event->getArgument('password'));
        });

    }

    /**
     * @param string $uid
     */
    public function failedLoginCallback($uid) {
        $this->throttle->addFailedLoginAttempt($uid, $this->request->getRemoteAddress());
    }

    /**
     * @param string $uid
     */
    public function postLoginCallback($uid) {
        $this->throttle->clearSuspiciousAttemptsForUidIpCombination($uid, $this->request->getRemoteAddress());
    }

    /**
     * @param string $uid
     * @throws LoginException
     */
    public function preLoginCallback($uid) {
        $this->throttle->applyBruteForcePolicy($uid, $this->request->getRemoteAddress());
    }
}
