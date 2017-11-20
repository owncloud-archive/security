# Security App
[![Build Status](https://travis-ci.org/owncloud/security.svg?branch=master)](https://travis-ci.org/owncloud/security)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/owncloud/security/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/owncloud/security/)

The security application currently has 2 features. Brute force protection and strong password enforcement.

# Brute Force Protection
It blocks an IP after certain failed login attempts

# Strong Password Enforcement
````
The admin can configure:
    - minimum length of the password
    - enforce upper and lower case characters
    - enforce numeric characters
    - enforce special characters (non-alphanumeric)
````

![](https://raw.githubusercontent.com/owncloud/security/43c55325cf09e5a8b81fafc358b08701aba81173/screenshots/settings.png)

It allows you to validate passwords in your own apps by using “OCP\User::validatePassword” event:

````
\OC::$server->getEventDispatcher()->dispatch(
    'OCP\User::validatePassword',
    new GenericEvent(null, ['password' => $password])
);
````