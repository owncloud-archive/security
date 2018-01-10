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


namespace OCA\Security\Tests\Db;

use OCA\Security\Db\DbService;
use OC\AppFramework\Utility\TimeFactory;
use OCA\Security\SecurityConfig;
use OCP\IDBConnection;
use Test\TestCase;

/**
 * @group DB
 */
class DbServiceTest extends TestCase {

    /** @var  DbService */
    private $dbService;

    /** @var  IDBConnection */
    private $connection;

    /** @var  TimeFactory */
    private $factory;

    /** @var \PHPUnit_Framework_MockObject_MockObject | SecurityConfig */
    private $configMock;

    /** @var string  */
    private $dbTable = 'failed_login_attempts';

    public function setUp() {
        parent::setUp();

        $this->connection = \OC::$server->getDatabaseConnection();
        $this->factory = new TimeFactory();
        $this->configMock = $this->getMockBuilder('OCA\Security\SecurityConfig')
            ->disableOriginalConstructor()
            ->getMock();
        $this->dbService = new DbService($this->connection, $this->factory, $this->configMock);

        $query = $this->connection->getQueryBuilder()->select('*')->from($this->dbTable);
        $result = $query->execute()->fetchAll();
        $this->assertEmpty($result, 'we need to start with a empty failed_login_attempts table');
    }

    public function tearDown() {
        parent::tearDown();
        $query = $this->connection->getQueryBuilder()->delete($this->dbTable);
        $query->execute();
    }

    public function testAddServer() {
        $ip = "192.168.1.1";
        $uid = "test";
        $this->dbService->addFailedLoginAttempt($uid, $ip);

        $query = $this->connection->getQueryBuilder()->select('*')->from($this->dbTable);
        $result = $query->execute()->fetchAll();
        $this->assertSame(1, count($result));
        $this->assertSame($ip, $result[0]['ip']);
        $this->assertSame($uid, $result[0]['uid']);
    }

    public function testGetSuspiciousActivityCountForUid() {
        $this->configMock->expects($this->once())
            ->method('getBruteForceProtectionTimeThreshold')
            ->willReturn('300');
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->assertEquals(2, $this->dbService->getSuspiciousActivityCountForUid('test1'));
    }

    public function testGetSuspiciousActivityCountForIp() {
        $this->configMock->expects($this->once())
            ->method('getBruteForceProtectionTimeThreshold')
            ->willReturn('300');
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->assertEquals(2, $this->dbService->getSuspiciousActivityCountForIp('192.168.1.1'));
    }

    public function testGetSuspiciousActivityCountForUidIpCombination() {
        $this->configMock->expects($this->once())
            ->method('getBruteForceProtectionTimeThreshold')
            ->willReturn('300');
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->dbService->addFailedLoginAttempt("test2", "192.168.1.1");
        $this->assertEquals(2, $this->dbService->getSuspiciousActivityCountForUidIpCombination('test1','192.168.1.1'));
    }

    public function testGetLastFailedLoginAttemptTimeForIp() {
        $this->configMock->expects($this->once())
            ->method('getBruteForceProtectionTimeThreshold')
            ->willReturn('300');
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $query = $this->connection->getQueryBuilder()->select('attempted_at')->from($this->dbTable);
        $result = $query->execute()->fetchAll();
        $this->assertEquals($this->dbService->getLastFailedLoginAttemptTimeForIp('192.168.1.1'), $result[1]['attempted_at']);
    }

    public function testDeleteSuspiciousAttemptsForIp() {
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->dbService->addFailedLoginAttempt("test2", "192.168.1.2");

        $query = $this->connection->getQueryBuilder()->select('*')->from($this->dbTable);
        $result = $query->execute()->fetchAll();
        $this->assertSame(2, count($result));
        $this->assertSame('test1', $result[0]['uid']);
        $this->assertSame('test2', $result[1]['uid']);
        $this->assertSame("192.168.1.1", $result[0]['ip']);
        $this->assertSame("192.168.1.2", $result[1]['ip']);

        $this->dbService->deleteSuspiciousAttemptsForIp("192.168.1.1");
        $query = $this->connection->getQueryBuilder()->select('*')->from($this->dbTable);
        $result = $query->execute()->fetchAll();
        $this->assertSame(1, count($result));
        $this->assertSame('test2', $result[0]['uid']);
        $this->assertSame("192.168.1.2", $result[0]['ip']);
    }
    public function testDeleteSuspiciousAttemptsForUidIpCombination() {
        $this->dbService->addFailedLoginAttempt("test1", "192.168.1.1");
        $this->dbService->addFailedLoginAttempt("test2", "192.168.1.1");

        $builder = $this->connection->getQueryBuilder();
        $query = $builder->select('*')->from($this->dbTable)
            ->Where($builder->expr()->eq('ip', $builder->createNamedParameter("192.168.1.1")));
        $result = $query->execute()->fetchAll();
        $this->assertSame(2, count($result));

        $this->dbService->deleteSuspiciousAttemptsForUidIpCombination('test1',"192.168.1.1");
        $query = $builder->select('*')->from($this->dbTable)
            ->Where($builder->expr()->eq('ip', $builder->createNamedParameter("192.168.1.1")));
        $result = $query->execute()->fetchAll();
        $this->assertSame(1, count($result));
    }
}
