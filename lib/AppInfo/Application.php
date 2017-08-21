<?php
/**
 *
 * @author Semih Serhat Karakaya
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
 *
 */
namespace OCA\Security\AppInfo;

use OCA\Security\SecurityConfig;
use \OCP\AppFramework\App;
use \OCA\Security\Throttle;
use \OCA\Security\Hooks;
use \OCA\Security\Db\DbService;
use \OCA\Security\PasswordValidator;

class Application extends App {

    public function __construct(array $urlParams=array()){
        parent::__construct('security', $urlParams);

        $container = $this->getContainer();

        $container->registerService('DbService', function($c) {
            return new DbService(
                $c->query('ServerContainer')->getDb(),
                $c->query('OCP\AppFramework\Utility\ITimeFactory'),
                $c->query('SecurityConfig')
            );
        });

        $container->registerService('Throttle', function($c) {
            return new Throttle(
                $c->query('DbService'),
                $c->query('SecurityConfig'),
                $c->query('OCP\IL10N'),
				$c->query('OCP\AppFramework\Utility\ITimeFactory')
            );
        });

        $container->registerService('SecurityConfig', function($c) {
            return new SecurityConfig(
                $c->query('OCP\IConfig')
            );
        });

        $container->registerService('PasswordValidator', function($c) {
            return new PasswordValidator(
                $c->query('SecurityConfig'),
                $c->query('OCP\IL10N')
            );
        });

        $container->registerService('Hooks', function($c) {
            return new Hooks(
                $c->query('ServerContainer')->getUserManager(),
                $c->query('Throttle'),
                $c->query('Request'),
                $c->query('PasswordValidator'),
                \OC::$server->getEventDispatcher()
            );
        });

    }
}