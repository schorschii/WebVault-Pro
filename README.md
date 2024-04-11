# XVault
XVault is a self-hosted/on-prem web based password safe with multi-language and multi-user support focused on enterprise usage. Passwords are stored RSA encrypted in a MySQL database and decryption only happens in the user's browser, providing true end-to-end encryption.

## Concept and Advantages
In contrast to conventional password safes, secrets are not encrypted with one static password, but individual with a per-user generated public/private key pair. This is done having enterprise usage in mind: employees should only have access to passwords they need as defined by group memberships, and not to the entire password safe. With this, there is no need to share a common master password which needs to be changed after one employee leaves the company.

LDAP authentication allows seamless integration into your companies environment. Access to the passwords can immediately be denied by disabling the LDAP user account. A flexible share function allows you to share passwords or entire password groups with specific co-workers or groups of users (you can use XVault as private password store if you don't share entries).

There is no database file which needs to be shared with all employees. Nobody except the administrator has access to the *encrypted* passwords. Attackers can't copy the user keys or encrypted passwords to run efficient brute force attacks against them.

Since de-/encryption only happens on the client side, passwords are still save since even if the communication between server and client is intercepted.

The web app is independent of the client platform and it is not necessary to install or deploy any client software.

## Screenshots
![Login page](.github/screenshot/login.png)
![Password Entries](.github/screenshot/vault.png)
![Password Entries - Dark Mode](.github/screenshot/vault-dark.png)

## Setup
### Server Requirements
Linux based server (Debian recommended) with Apache 2, PHP 7.4+ and MySQL/MariaDB.

This app is mainly intended for usage with LDAP directories. Local user accounts are implemented too but only used for development or testing purposes.

### Server Installation
0. Install dependencies: `apache2 libapache2-mod-php php php-ldap`
1. Set the applications `public` directory as your webservers root directory (if necessary, create a virtual host for this application on your webserver).
2. Run `composer install` inside the application root directory to install the dependencies.
3. Create an empty database on your MySQL server and import the schema from the `sql/SCHEMA.sql` file. Then, create `config/settings.php` from `config/settings.php.example` and enter your MySQL connection credentials, LDAP connection and various other parameters. Read the comments in the example file for more information.
4. Ensure that `AllowOverride All` is set for your application directory in your Apache configuration.
5. Thats it. Open a webbrowser, navigate to your installation and log in with a LDAP account.
6. Set up HTTPS on you webserver. This is necessary since web browsers expose the crypto API only in secure contexts. Redirect all HTTP requests to HTTPS. Use at least a RSA 4096 bit key pair (certificate) or elliptic curve crypto.

### Hardening Recommendations
- Transfer the ownership of the application files to root and deny write access for all other users. The web server user (www-data) should only be able to read the application files.
- Use strong passwords for your Linux system users and MySQL accounts.
- Do not run other applications on the same server.
- Ensure that the MySQL server only listens for requests from localhost and not from other computers inside your network. Do not use tools like phpMyAdmin on your production server.
- Install `fail2ban` to limit brute force attacks.
- Keep your server always up to date by enabling `unattended-upgrades`.
- Limit access to the IP addresses/ranges that really need it, e.g. via Apache or firewall rules.

### Client Requirements
Crypto API capable browser with Javascript enabled
- Chrome/Chromium based browsers, Firefox (both desktop and mobile)
- IE/Edge are **not** supported

### Upgrade notes for v0.x (WebPW) users
Since the concept and database schema of XVault differs completely from v0.x ("WebPW"), there is no direct upgrade path. You need to manually export and re-import your passwords in the new version.

## FAQ
### I'm not able to share passwords with some users, they are disabled in the select box
The user account doesn't have a keypair yet. Users need to log in once before passwords can be shared with them.

## Roadmap
- shares with r/o permission
- file storage support
- custom entry icons

## Support
You need support or specific adjustments for your environment? You can hire me to extend this project to your needs. Please [contact me](https://georg-sieber.de/?page=impressum) if you are interested.

Found a bug? Great! Please report it (preferably with a ready-to-use fix as pull request) on GitHub. Questions, ideas, feature requests or just (hopeful positive) feedback is also welcome.
