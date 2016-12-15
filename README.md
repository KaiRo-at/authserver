# KaiRo.at Auth Server
This authentication server solution aims to provide a login service based on Auth2 to run on your own servers and use in your websites.
It's written in PHP and should work with recent PHP5 as well as PHP7, and the web UI should work in modern browsers and down to IE8.

For installing, do the follwing:

* git clone git@github.com:KaiRo-at/authserver.git
* cd authserver
* composer install
* git clone git@github.com:KaiRo-at/php-utility-classes.git

After that, integrate a config similar to [vhost.authserver.conf](etc/apache/vhost.authserver.conf) to your Apache configuration,
create a user and empty MySQL database for the authentication service,
copy [auth_settings.json](etc/kairo/auth_settings.json) to /etc/kairo and adapt it to your needs.

You'll have to at least put in the database name/user/password and insert one nonce into the array, generated with |openssl rand -base64 48|.
Note: if you have a security issue that could have someone else read the settings file, add a new nonce at the end of the array. NEVER remove a nonce or existing passwords will all be invalid!
People's password hashes will be migrated to the new nonce when they log in the next time.
The system of having a nonce saved on disk in addition to the salt that is included in the password in the database increases security by needing a hacker to get both the database and the on-disk configuration to even do offline brute-force cracking attempts.

If you want to use Piwik with this service, either install it via composer or use a distribution-provided package and point the Apache config and settings to it.

Please don't use GitHub for issue tracking but http://bugzilla.kairo.at/ - Product: KaiRo Software, Component: Authentication Service
