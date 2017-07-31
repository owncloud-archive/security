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


use OCA\Security\Hooks;
use Test\TestCase;

class HooksTest extends TestCase {

    /** @var  Hooks */
    private $hooks;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $userManagerMock;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $throttleMock;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $requestMock;

    public function setUp() {
        parent::setUp();

        $this->userManagerMock = $this->getMockBuilder('OCP\IUserManager')
            ->disableOriginalConstructor()
            ->getMock();

        $this->throttleMock = $this->getMockBuilder('OCA\Security\Throttle')
            ->disableOriginalConstructor()
            ->getMock();
        $this->requestMock = $this->getMockBuilder('OCP\IRequest')
            ->disableOriginalConstructor()
            ->getMock();

        $this->hooks = $this->getMockBuilder('OCA\Security\Hooks')
            ->setConstructorArgs(
                [
                    $this->userManagerMock,
                    $this->throttleMock,
                    $this->requestMock
                ]
            )->setMethods()->getMock();
    }

    public function testFailedLoginCallback() {
        $this->throttleMock->expects($this->once())
            ->method('addFailedLoginAttempt');
        $this->throttleMock->expects($this->once())
            ->method('putDelay');

        $this->hooks->failedLoginCallback("test");
        $this->assertTrue(true);
    }

    public function testPostLoginCallback() {
        $this->throttleMock->expects($this->once())
            ->method('clearSuspiciousAttemptsForIp');
        $user = $this->getMockBuilder('OCP\IUser')
            ->disableOriginalConstructor()
            ->getMock();

        $this->hooks->postLoginCallback($user);
        $this->assertTrue(true);
    }
}
