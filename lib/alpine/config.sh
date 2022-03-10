#!/bin/bash
# lib/alpine/config.sh
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#    any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
[[ -z $packages ]] && packages="coreutils openrc apache2 bc cdrkit curl gcc shadow g++ git gzip lftp linux-headers m4 make mariadb mariadb-client net-tools nfs-utils openssh openssl perl perl-crypt-passwdmd5 php7 php7-session php7-fpm php7-curl php7-ftp php7-gd php7-gettext php7-ldap php7-mysqli php7-openssl php7-pdo_mysql php7-sockets php7-pecl-mcrypt php7-mysqli php7-json php7-pcntl php7-posix tar tftp-hpa wget"
[[ -z $packageinstaller ]] && packageinstaller="apk add"
[[ -z $packagelist ]] && packagelist="apk info"
[[ -z $packageupdater ]] && packageupdater="apk update && apk upgrade"
[[ -z $packmanUpdate ]] && packmanUpdate="$packageinstaller"
[[ -z $packageQuery ]] && packageQuery="apk info -e \$x "
[[ -z $langPackages ]] && langPackages="iso-codes"
[[ -z $dhcpname ]] && dhcpname=""
if [[ -z $webdirdest ]]; then
    if [[ -z $docroot ]]; then
        docroot="/var/www/"
        webdirdest="${docroot}fog/"
    elif [[ "$docroot" != *'fog'* ]]; then
        webdirdest="${docroot}fog/"
    else
        webdirdest="${docroot}/"
    fi
fi
[[ -z $webredirect ]] && webredirect="${webdirdest}/index.php"
[[ -z $apacheuser ]] && apacheuser="apache"
[[ -z $apachelogdir ]] && apachelogdir="/var/log/apache2"
[[ -z $apacheerrlog ]] && apacheerrlog="$apachelogdir/error.log"
[[ -z $apacheacclog ]] && apacheacclog="$apachelogdir/access.log"
[[ -z $httpdconf ]] && httpdconf="/etc/apache2/httpd.conf"
[[ -z $etcconf ]] && etcconf="/etc/apache2/conf.d/001-fog.conf"
[[ -z $phpini ]] && phpini="/etc/php7/php.ini"
[[ -z $storageLocation ]] && storageLocation="/images"
[[ -z $storageLocationCapture ]] && storageLocationCapture="${storageLocation}/dev"
[[ -z $dhcpconfig ]] && dhcpconfig="/etc/dhcpd.conf"
[[ -z $dhcpconfigother ]] && dhcpconfigother="/etc/dhcp/dhcpd.conf"
[[ -z $tftpdirdst ]] && tftpdirdst="/var/tftpboot"
[[ -z $tftpconfig ]] && tftpconfig="/etc/xinetd.d/tftpd"
[[ -z $ftpxinetd ]] && ftpxinetd="/etc/xinetd.d/vsftpd"
[[ -z $ftpconfig ]] && ftpconfig="/etc/vsftpd.conf"
[[ -z $dhcpd ]] && dhcpd="dhcpd4"
[[ -z $snapindir ]] && snapindir="/opt/fog/snapins"
[[ -z $php_ver ]] && php_ver="7"
[[ -z $phpfpm ]] && phpfpm="php-fpm${php_ver}"
