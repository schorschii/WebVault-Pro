# WebPW
Web based password safe with multi-language, multi-user and file upload support.

## About
* © 2017 Georg Sieber - http://georg-sieber.de
* licensed under the terms of the GPLv2 (see LICENSE.txt)
* using Slim Framework & Twig Template Engine
* https://github.com/schorschii/webpw

## Description
Store and view your passwords platform-independent with this PHP web application. Passwords are saved AES-encrypted in a MySQL database. You can create multiple vaults with different master passwords, e.g. for different departments in your company. Inside of vaults you can group password entries and search them.

## Screenshots
![Login page](https://raw.githubusercontent.com/schorschii/webpw/master/public/img/screenshot/1.png)
![Password entries](https://raw.githubusercontent.com/schorschii/webpw/master/public/img/screenshot/2.png)
![View password entry](https://raw.githubusercontent.com/schorschii/webpw/master/public/img/screenshot/3.png)

## Advantages over conventional password safe applications
- There is no database file which you need to share -for example- with your co-workers - this means that nobody (except the administrator) has access to the encrypted passwords. Attackers can't copy this file and run brute force attacks against it.
- You can safely store files with WebPW.
- It is not necessary to install or deploy any client software.
- You can create multiple vaults for different purposes or persons within one WebPW installation and MySQL database.

## Setup
### Server
To set up this web app you need a database (MySQL, MariaDB) server and a Linux-based apache webserver running PHP 7.
  1. Set the applications `public` directory as your webservers root directory (if necessary, create a virtual host for this application on your webserver).
  2. Run `composer install -o` inside the application root directory to install the dependencies.
  3. Edit `config/database.php` and enter your MySQL connection credentials.
  4. Ensure that `AllowOverride All` is set for your application directory in your apache configuration.
  5. Open `http://<ADDRESS_OF_YOUR_WEBSERVER>/setup` in a webbrowser and follow the setup.
  6. Thats it. You can now log in on the "Manage Vaults" page with the management password you haven chosen in the previous step and create a vault. After that, you can open this newly created vault and store your passwords.
  7. (optional) You can set your preferred language as default language in `config/general.php` file.

### Recommendations for hardening your server
  - It is highly recommended to use HTTPS instead of HTTP (except you are accessing the site only via localhost). Redirect all HTTP requests to HTTPS.
  - Transfer the ownership of the application files to the web server user (www-data) and deny access for all other users.
  - Use strong passwords for the linux root user (other users too) and mysql accounts.
  - Ensure, that the database server only listens for requests from localhost (and not from other computers inside your network).
  - Do not install tools like `phpmyadmin`.
  - Disable or uninstall the SSH server.
  - Keep your server always up to date.
  - Use an additional apache authentication for the application directory. If you use WebPW inside a company you can use apache's ldap authentication.
  - Limit the access to the IP addresses that really need it.

### Client
  - Chrome/Chromium, Firefox, Opera (both desktop and mobile)
  - IE/Edge not tested yet
  - works without JavaScript, but then some features are disabled (search)

## License
GNU General Public License - see LICENSE.txt

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to:
Free Software Foundation, Inc.
59 Temple Place - Suite 330
Boston, MA  02111-1307, USA.

## Libraries
This web application uses:  

[parseCSV][] library  
© 2014 Jim Myhrberg (MIT license)  

[Slim][] framework  
© 2011-2017 Josh Lockhart (MIT license)  

[Twig][] template engine  
© 2009-2017 the Twig Team (BSD 3-clause)  

[illuminate/database][] toolkit  
© Taylor Otwell (MIT license)  

[parseCSV]: https://github.com/parsecsv/parsecsv-for-php
[Slim]: https://github.com/slimphp/Slim
[Twig]: https://github.com/twigphp/Twig
[illuminate/database]: https://packagist.org/packages/illuminate/database

## Support
Found a bug? Great! Please report it (preferably with a ready-to-use fix for it ;-) ) on GitHub. Questions, ideas and feature requests are also welcome.

## ToDo and planned features
Please visit the GitHub page for more information.
