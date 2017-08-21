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


namespace OCA\Security\Tests;


use OC\User\Manager;
use OCA\Security\Hooks;
use OCA\Security\PasswordValidator;
use OCA\Security\Throttle;
use OCP\IRequest;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Test\TestCase;

class HooksTest extends TestCase {

    /** @var  Hooks */
    private $hooks;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject | Manager
     */
    private $userManagerMock;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject | Throttle
     */
    private $throttleMock;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject | IRequest
     */
    private $requestMock;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject | PasswordValidator
     */
    private $passwordValidatorMock;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject | EventDispatcher
     */
    private $dispatcherMock;

    public function setUp() {
        parent::setUp();

        $this->userManagerMock = $this->getMockBuilder('\OC\User\Manager')
            ->disableOriginalConstructor()
            ->getMock();

        $this->throttleMock = $this->getMockBuilder('OCA\Security\Throttle')
            ->disableOriginalConstructor()
            ->getMock();
        $this->requestMock = $this->getMockBuilder('OCP\IRequest')
            ->disableOriginalConstructor()
            ->getMock();
        $this->passwordValidatorMock = $this->getMockBuilder('OCA\Security\PasswordValidator')
            ->disableOriginalConstructor()
            ->getMock();
        $this->dispatcherMock = $this->getMockBuilder(EventDispatcher::class)
            ->disableOriginalConstructor()
            ->getMock();

        $this->hooks = new Hooks(
            $this->userManagerMock,
            $this->throttleMock,
            $this->requestMock,
            $this->passwordValidatorMock,
            $this->dispatcherMock);
    }

    public function testRegister() {
        $this->userManagerMock->expects($this->exactly(3))
            ->method('listen');
        $this->dispatcherMock->expects($this->once())
            ->method('addListener');
        $this->hooks->register();
    }

    public function testFailedLoginCallback() {
        $this->throttleMock->expects($this->once())
            ->method('addFailedLoginAttempt');

        $this->hooks->failedLoginCallback("test");
        $this->assertTrue(true);
    }

    public function testPostLoginCallback() {
        $this->throttleMock->expects($this->once())
            ->method('clearSuspiciousAttemptsForIp');

        $this->hooks->postLoginCallback();
        $this->assertTrue(true);
    }

    public function testPreLoginCallback() {
        $this->throttleMock->expects($this->once())
            ->method('applyBruteForcePolicy');

        $this->hooks->preLoginCallback();
        $this->assertTrue(true);
    }
}
