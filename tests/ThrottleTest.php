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


use OCA\Security\Db\DbService;
use OCA\Security\Throttle;
use Test\TestCase;

class ThrottleTest extends TestCase {

    /** @var \PHPUnit_Framework_MockObject_MockObject | Throttle */
    private $throttle;
    /**
     * @var \PHPUnit_Framework_MockObject_MockObject | DbService
     */
    private $dbServiceMock;

    public function setUp() {
        parent::setUp();

        $this->dbServiceMock = $this->getMockBuilder('OCA\Security\Db\DbService')
            ->disableOriginalConstructor()
            ->getMock();

        $this->throttle = $this->getMockBuilder('OCA\Security\Throttle')
            ->setConstructorArgs(
                [
                    $this->dbServiceMock
                ]
            )->setMethods()->getMock();
    }

    public function testAddFailedLoginAttempt() {
        $this->dbServiceMock->expects($this->once())->method('addFailedLoginAttempt')
            ->with('test', '192.168.1.1');

        $this->throttle->addFailedLoginAttempt('test', '192.168.1.1');
    }

    public function testPutDelay() {

        /** @var \PHPUnit_Framework_MockObject_MockObject | Throttle $throttle */
        $throttle = $this->getMockBuilder('OCA\Security\Throttle')
            ->setConstructorArgs(
                [
                    $this->dbServiceMock
                ]
            )->setMethods(['calculateDelayForIp'])->getMock();

        $throttle->expects($this->once())->method('calculateDelayForIp')
            ->with('192.168.1.1');

        $throttle->putDelay('test', '192.168.1.1');
    }

    public function testCalculateDelayForUid() {
        $this->dbServiceMock->expects($this->once())->method('getSuspiciousActivityCountForUid')
            ->with('test')
            ->willReturn(2);

        $this->assertEquals(2, $this->throttle->calculateDelayForUid('test'));
    }

    public function testCalculateDelayForIp() {
        $this->dbServiceMock->expects($this->once())->method('getSuspiciousActivityCountForIp')
            ->with('192.168.1.1')
            ->willReturn(5);

        $this->assertEquals(5, $this->throttle->calculateDelayForIp('192.168.1.1'));
    }

    public function testClearSuspiciousAttemptsForIp() {
        $this->dbServiceMock->expects($this->once())->method('deleteSuspiciousAttemptsForIp')
            ->with('192.168.1.1');

        $this->throttle->clearSuspiciousAttemptsForIp('192.168.1.1');
    }
}
