# WebPW
Web based password safe with multi-language support.

## About
* (c) 2017 Georg Sieber - http://georg-sieber.de
* licensed under the terms of the GPLv2 (see LICENSE.txt)
* view source and fork me on GitHub: https://github.com/schorschii/webpw

## Description
Store and view your passwords platform-independent with this PHP web application. Passwords are saved AES-encrypted in an MySQL database. You can create multiple vaults with different master passwords, e.g. for different departments in your company. Inside of vaults you can group passwords entries.

## Screenshots
![Login page](https://raw.githubusercontent.com/schorschii/webpw/master/img/screenshot/1.png)
![Password entries](https://raw.githubusercontent.com/schorschii/webpw/master/img/screenshot/2.png)
![Vault management](https://raw.githubusercontent.com/schorschii/webpw/master/img/screenshot/3.png)

## Setup
### Server
To set up this web app you need a database (MySQL) server and an Linux-based apache webserver running PHP 7.
  1. Copy all files into a directory of your choice.
  2. Edit "database.php" and enter your MySQL connection credentials.
  3. Open the "setup.php" file in your webbrowser to create the required tables in your database.
  4. Open the directory in your webbrowser (the webserver will serve the index.php file to you). Thats it. You can now log in on the "Manage Vaults" page with the management passwort you haven chosen in the previous step and create a vault. After that, you can open this newly created vault and store your passwords.
  5. It is highly recommended to use HTTPS instead of HTTP! Set up your webserver appropriate.
  6. (Optional) You can set your preferred language as default language in "global.php" file.

### Client
  - Chrome/Chromium, Firefox, Opera (both desktop and mobile)
  - IE/Edge not tested yet

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

## Support
Found a bug? Great!  
Please report it (preferably with a ready-to-use fix for it ;-) ) on GitHub.
Questions, ideas and feature requests are also welcome.


## ToDo and planned features
Visit the GitHub page for more information.
