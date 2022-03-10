#!/bin/bash
#  FOG is a computer imaging solution.
#  Copyright (C) 2007  Chuck Syperski & Jian Zhang
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

configureUsers() {
    userexists=0
    [[ -z $username || "x$username" = "xfog" ]] && username='fogproject'
    dots "Setting up $username user"
    if [[ ! -f "/var/log/lastlog" ]]; then
        touch /var/log/lastlog
    fi
    getent passwd $username > /dev/null
    if [[ $? -eq 0 ]]; then
        if [[ ! -f "$fogprogramdir/.fogsettings" && ! -x /home/$username/warnfogaccount.sh ]]; then
            echo "Already exists"
            echo
            echo "The account \"$username\" already exists but this seems to be a"
            echo "fresh install. We highly recommend to NOT creating this account"
            echo "beforehand as it is supposed to be a system account not meant"
            echo "to be used to login and work on the machine!"
            echo
            echo "Please remove the account \"$username\" manually before running"
            echo "the installer again. Run: userdel $username"
            echo
            exit 1
        else
            lastlog -u $username | tail -n -1 | grep "\*\*.*\*\*" > /dev/null 2>&1
            if [[ $? -eq 1 ]]; then
                echo "Already exists"
                echo
                echo "The account \"$username\" already exists and has been used to"
                echo "logon and work on this machine. We highly recommend you NOT"
                echo "use this account for your work as it is supposed to be a"
                echo "system account!"
                echo
                echo "Please remove the account \"$username\" manually before running"
                echo "the installer again. Run: userdel $username"
                echo
                exit 1
            fi
            echo "Skipped"
        fi
    else
        addgroup -S ${username} >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        adduser -s "/bin/bash" -h "/home/${username}" -S ${username} >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        touch "/home/${username}/.bashrc"
        chown $username:$username "/home/${username}/.bashrc"
		errorStat $?
    fi
    if [[ ! -d /home/$username ]]; then
        echo "# It has been noticed that your $username home folder is missing, #"
        echo "#   has been deleted, or has been moved.                          #"
        echo "# This may cause issues with capturing images and snapin uploads. #"
        echo "# If you this move/delete was unintentional you can run:          #"
        echo " userdel $username"
        echo " useradd -s \"/bin/bash\" -d \"/home/$username\" -m \"$username\""
        #userdel $username
        #useradd -s "/bin/bash" -d "/home/${username}" -m ${username} >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        #errorStat $?
    fi
		dots "Locking $username as a system account"
		textmessage="You seem to be using the '$username' system account to logon and work \non your FOG server system.\n\nIt's NOT recommended to use this account! Please create a new \naccount for administrative tasks.\n\nIf you re-run the installer it would reset the 'fog' account \npassword and therefore lock you out of the system!\n\nTake care, \nyour FOGproject team"
		grep -q "exit 1" /home/$username/.bashrc || cat >>/home/$username/.bashrc <<EOF

echo -e "$textmessage"
exit 1
EOF
    mkdir -p /home/$username/.config/autostart/
    cat >/home/$username/.config/autostart/warnfogaccount.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Warn users to not use the $username account
Exec=/home/$username/warnfogaccount.sh
Comment=Warn users who use the $username system account to logon
EOF
    chown -R $username:$username /home/$username/.config/
    cat >/home/$username/warnfogaccount.sh <<EOF
#!/bin/bash
title="FOG system account"
text="$textmessage"
z=\$(which zenity)
x=\$(which xmessage)
n=\$(which notify-send)
if [[ -x "\$z" ]]
then
    \$z --error --width=480 --text="\$text" --title="\$title"
elif [[ -x "\$x" ]]
then
    echo -e "\$text" | \$x -center -file -
else
    \$n -u critical "\$title" "\$(echo \$text | sed -e 's/ \\n/ /g')"
fi
EOF
    chmod 755 /home/$username/warnfogaccount.sh
    chown $username:$username /home/$username/warnfogaccount.sh
    errorStat $?
    dots "Setting up $username password"
    if [[ -z $password ]]; then
        [[ -f $webdirdest/lib/fog/config.class.php ]] && password=$(awk -F '"' -e '/TFTP_FTP_PASSWORD/,/);/{print $2}' $webdirdest/lib/fog/config.class.php | grep -v "^$")
    fi
    if [[ -n "$(checkPasswordChars)" ]]
    then
        echo "Failed"
        echo "# The fog system account password includes characters we cannot properly"
        echo "# handle. Please remove the following character(s) from the password in"
        echo "# your .fogsettings file before re-running the installer: $passcheck"
        exit 1
    fi
    cnt=0
    ret=999
    while [[ $ret -ne 0 && $cnt -lt 10 ]]
    do
        [[ -z $password || $ret -ne 999 ]] && password=$(generatePassword 20)
        echo -e "$password\n$password" | passwd $username >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        ret=$?
        let cnt+=1
    done
    errorStat $ret
    unset cnt
    unset ret
}

configureMySql() {
    stopInitScript
    dots "Setting up and starting MySQL"
    dbservice=$(service -l | grep -o -e "mariadb" -e "mysqld" -e "mysql" | tr -d '@')
    for mysqlconf in $(grep -rsl '.*skip-networking' /etc | grep -v init.d); do
        sed -i '/.*skip-networking/ s/^#*/#/' -i $mysqlconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    done
    for mysqlconf in `grep -rsl '.*bind-address.*=.*127.0.0.1' /etc | grep -v init.d`; do
        sed -e '/.*bind-address.*=.*127.0.0.1/ s/^#*/#/' -i $mysqlconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    done
    service mariadb setup >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    service mariadb start >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    # if someone still has DB user root set in .fogsettings we want to change that
    [[ "x$snmysqluser" == "xroot" ]] && snmysqluser='fogmaster'
    [[ -z $snmysqlpass ]] && snmysqlpass=$(generatePassword 20)
    [[ -n $snmysqlhost ]] && host="--host=$snmysqlhost"
    sqloptionsroot="${host} --user=root"
    sqloptionsuser="${host} -s --user=${snmysqluser}"
    mysqladmin $host ping >/dev/null 2>&1 || mysqladmin $host ping >/dev/null 2>&1 || mysqladmin $host ping >/dev/null 2>&1
    errorStat $?

    dots "Setting up MySQL user and database"
    mysql $sqloptionsroot --execute="quit" >/dev/null 2>&1
    connect_as_root=$?
    if [[ $connect_as_root -eq 0 ]]; then
        mysqlrootauth=$(mysql $sqloptionsroot --database=mysql --execute="SELECT Host,User,plugin FROM user WHERE Host='localhost' AND User='root' AND plugin='unix_socket'")
        if [[ -z $mysqlrootauth && -z $autoaccept ]]; then
            echo
            echo "   The installer detected a blank database *root* password. This"
            echo "   is very common on a new install or if you upgrade from any"
            echo "   version of FOG before 1.5.8. To improve overall security we ask"
            echo "   you to supply an appropriate database *root* password now."
            echo
            echo "   NOTICE: Make sure you choose a good password but also one"
            echo "   you can remember or use a password manager to store it."
            echo "   The installer won't store the given password in any place"
            echo "   and it will be lost right after the installer finishes!"
            echo
            echo -n "   Please enter a new database *root* password to be set: "
            read -rs snmysqlrootpass
            echo
            echo
            if [[ -z $snmysqlrootpass ]]; then
                snmysqlrootpass=$(generatePassword 20)
                echo
                echo "   We don't accept a blank database *root* password anymore and"
                echo "   will generate a password for you to use. Please make sure"
                echo "   you save the following password in an appropriate place as"
                echo "   the installer won't store it for you."
                echo
                echo "   Database root password: $snmysqlrootpass"
                echo
                echo "   Press [Enter] to procede..."
                read -rs procede
                echo
                echo
            fi
            # WARN: Since MariaDB 10.3 (maybe earlier) setting a password when auth plugin is
            # set to unix_socket will actually switch to auth plugin mysql_native_password
            # automatically which was not the case in MariaDB 10.1 and is causing trouble.
            # So now we try to be more conservative and only reset the pass when we get one
            # to make sure the user is in charge of this.
            mysqladmin $sqloptionsroot password "${snmysqlrootpass}" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        fi
        snmysqlstoragepass=$(mysql -s $sqloptionsroot --password="${snmysqlrootpass}" --execute="SELECT settingValue FROM globalSettings WHERE settingKey LIKE '%FOG_STORAGENODE_MYSQLPASS%'" $mysqldbname 2>/dev/null | tail -1)
    else
        snmysqlstoragepass=$(mysql $sqloptionsuser --password="${snmysqlpass}" --execute="SELECT settingValue FROM globalSettings WHERE settingKey LIKE '%FOG_STORAGENODE_MYSQLPASS%'" $mysqldbname 2>/dev/null | tail -1)
    fi
    mysql $sqloptionsuser --password="${snmysqlpass}" --execute="quit" >/dev/null 2>&1
    connect_as_fogmaster=$?
    mysql ${host} -s --user=fogstorage --password="${snmysqlstoragepass}" --execute="quit" >/dev/null 2>&1
    connect_as_fogstorage=$?
    if [[ $connect_as_fogmaster -eq 0 && $connect_as_fogstorage -eq 0 ]]; then
        echo "Skipped"
        return
    fi

    # If we reach this point it's clear that this install is not setup with
    # unpriviledged DB users yet and we need to have root DB access now.
    if [[ $connect_as_root -ne 0 ]]; then
        echo
        echo "   To improve the overall security the installer will create an"
        echo "   unpriviledged database user account for FOG's database access."
        echo "   Please provide the database *root* user password. Be asured"
        echo "   that this password will only be used while the FOG installer"
        echo -n "   is running and won't be stored anywhere: "
        read -rs snmysqlrootpass
        echo
        echo
        mysql $sqloptionsroot --password="${snmysqlrootpass}" --execute="quit" >/dev/null 2>&1
        if [[ $? -ne 0 ]]; then
            echo "   Unable to connect to the database using the given password!"
            echo -n "   Try again: "
            read -rs snmysqlrootpass
            mysql $sqloptionsroot --password="${snmysqlrootpass}" --execute="quit" >/dev/null 2>&1
            if [[ $? -ne 0 ]]; then
                echo
                echo "   Failed! Terminating installer now."
                exit 1
            fi
        fi
    fi

    snmysqlstoragepass=$(mysql -s $sqloptionsroot --password="${snmysqlrootpass}" --execute="SELECT settingValue FROM globalSettings WHERE settingKey LIKE '%FOG_STORAGENODE_MYSQLPASS%'" $mysqldbname 2>/dev/null | tail -1)
    # generate a new fogstorage password if it doesn't exist yet or if it's old style fs0123456789
    if [[ -z $snmysqlstoragepass ]]; then
        snmysqlstoragepass=$(generatePassword 20)
    elif [[ -n $(echo $snmysqlstoragepass | grep "^fs[0-9][0-9]*$") ]]; then
        snmysqlstoragepass=$(generatePassword 20)
        echo
        echo "   The current *fogstorage* database password does not meet high"
        echo "   security standards. We will generate a new password and update"
        echo "   all the settings on this FOG server for you. Please take note"
        echo "   of the following credentials that you need to manually update"
        echo "   on all your storage nodes' /opt/fog/.fogsettings configuration"
        echo "   files and re-run (!) the FOG installer:"
        echo "   snmysqluser='fogstorage'"
        echo "   snmysqlpass='${snmysqlstoragepass}'"
        echo
        if [[ -z $autoaccept ]]; then
            echo "   Press [Enter] to proceed after you noted down the credentials."
            read
        fi
    fi
    [[ ! -d ../tmp/ ]] && mkdir -p ../tmp/ >/dev/null 2>&1
    cat >../tmp/fog-db-and-user-setup.sql <<EOF
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ANSI' ;
DELETE FROM mysql.user WHERE User='' ;
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1') ;
DROP DATABASE IF EXISTS test ;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%' ;
CREATE DATABASE IF NOT EXISTS $mysqldbname ;
USE $mysqldbname ;
DROP PROCEDURE IF EXISTS $mysqldbname.create_user_if_not_exists ;
DELIMITER $$
CREATE PROCEDURE $mysqldbname.create_user_if_not_exists()
BEGIN
  DECLARE masteruser BIGINT DEFAULT 0 ;
  DECLARE storageuser BIGINT DEFAULT 0 ;

  SELECT COUNT(*) INTO masteruser FROM mysql.user
    WHERE User = '${snmysqluser}' and  Host = '${snmysqlhost}' ;
  IF masteruser > 0 THEN
    DROP USER '${snmysqluser}'@'${snmysqlhost}';
  END IF ;
  CREATE USER '${snmysqluser}'@'${snmysqlhost}' IDENTIFIED BY '${snmysqlpass}' ;
  GRANT ALL PRIVILEGES ON $mysqldbname.* TO '${snmysqluser}'@'${snmysqlhost}' ;

  SELECT COUNT(*) INTO storageuser FROM mysql.user
    WHERE User = 'fogstorage' and  Host = '%' ;
  IF storageuser > 0 THEN
    DROP USER 'fogstorage'@'%';
  END IF ;
  CREATE USER 'fogstorage'@'%' IDENTIFIED BY '${snmysqlstoragepass}' ;
END ;$$
DELIMITER ;
CALL $mysqldbname.create_user_if_not_exists() ;
DROP PROCEDURE IF EXISTS $mysqldbname.create_user_if_not_exists ;
FLUSH PRIVILEGES ;
SET SQL_MODE=@OLD_SQL_MODE ;
EOF
    mysql $sqloptionsroot --password="${snmysqlrootpass}" <../tmp/fog-db-and-user-setup.sql >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
}

createSSLCA() {
    if [[ -z $sslpath ]]; then
        [[ -d /opt/fog/snapins/CA && -d /opt/fog/snapins/ssl ]] && mv /opt/fog/snapins/CA /opt/fog/snapins/ssl/
        sslpath='/opt/fog/snapins/ssl/'
    fi
    if [[ $recreateCA == yes || $caCreated != yes || ! -e $sslpath/CA || ! -e $sslpath/CA/.fogCA.key ]]; then
        mkdir -p $sslpath/CA >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        dots "Creating SSL CA"
        openssl genrsa -out $sslpath/CA/.fogCA.key 4096 >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        openssl req -x509 -new -sha512 -nodes -key $sslpath/CA/.fogCA.key -days 3650 -out $sslpath/CA/.fogCA.pem >>$workingdir/error_logs/fog_error_${version}.log 2>&1 << EOF
.
.
.
.
.
FOG Server CA
.
EOF
        errorStat $?
    fi
    [[ -z $sslprivkey ]] && sslprivkey="$sslpath/.srvprivate.key"
    if [[ $recreateKeys == yes || $recreateCA == yes || $caCreated != yes || ! -e $sslpath || ! -e $sslprivkey ]]; then
        dots "Creating SSL Private Key"
        if [[ $(validip $ipaddress) -ne 0 ]]; then
            echo -e "\n"
            echo "  You seem to be using a DNS name instead of an IP address."
            echo "  This would cause an error when generating SSL key and certs"
            echo "  and so we will stop here! Please adjust variable 'ipaddress'"
            echo "  in .fogsettings file if this is an update and make sure you"
            echo "  provide an IP address when re-running the installer."
            exit 1
        fi
        mkdir -p $sslpath >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        openssl genrsa -out $sslprivkey 4096 >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        cat > $sslpath/req.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = yes
[req_distinguished_name]
CN = $ipaddress
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = $ipaddress
DNS.1 = $hostname
EOF
        openssl req -new -sha512 -key $sslprivkey -out $sslpath/fog.csr -config $sslpath/req.cnf >>$workingdir/error_logs/fog_error_${version}.log 2>&1 << EOF
$ipaddress
EOF
        errorStat $?
    fi
    [[ ! -e $sslpath/.srvprivate.key ]] && ln -sf $sslprivkey $sslpath/.srvprivate.key >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    dots "Creating SSL Certificate"
    mkdir -p $webdirdest/management/other/ssl >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    cat > $sslpath/ca.cnf << EOF
[v3_ca]
subjectAltName = @alt_names
[alt_names]
IP.1 = $ipaddress
DNS.1 = $hostname
EOF
    openssl x509 -req -in $sslpath/fog.csr -CA $sslpath/CA/.fogCA.pem -CAkey $sslpath/CA/.fogCA.key -CAcreateserial -out $webdirdest/management/other/ssl/srvpublic.crt -days 3650 -extensions v3_ca -extfile $sslpath/ca.cnf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
    dots "Creating auth pub key and cert"
    cp $sslpath/CA/.fogCA.pem $webdirdest/management/other/ca.cert.pem >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    openssl x509 -outform der -in $webdirdest/management/other/ca.cert.pem -out $webdirdest/management/other/ca.cert.der >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
    dots "Resetting SSL Permissions"
    chown -R $apacheuser:$apacheuser $webdirdest/management/other >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
    [[ $httpproto == https ]] && sslenabled=" (SSL)" || sslenabled=" (no SSL)"
    dots "Setting up Apache virtual host${sslenabled}"
    case $novhost in
        [Yy]|[Yy][Ee][Ss])
            echo "Skipped"
            ;;
        *)
                if [[ $osid -eq 2 ]]; then
                    a2dissite 001-fog >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    a2ensite 000-default >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                fi
                mv -fv "${etcconf}" "${etcconf}.${timestamp}" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                echo "<VirtualHost *:80>" > "$etcconf"
                echo "    <FilesMatch \"\.php\$\">" >> "$etcconf"
                if [[ $osid -eq 1 && $OSVersion -lt 7 ]]; then
                    echo "        SetHandler application/x-httpd-php" >> "$etcconf"
                else
                    echo "        SetHandler \"proxy:fcgi://127.0.0.1:9000/\"" >> "$etcconf"
                fi
                echo "    </FilesMatch>" >> "$etcconf"
                echo "    ServerName $ipaddress" >> "$etcconf"
                echo "    ServerAlias $hostname" >> "$etcconf"
                echo "    DocumentRoot $docroot" >> "$etcconf"
                if [[ $httpproto == https ]]; then
                    echo "    RewriteEngine On" >> "$etcconf"
                    echo "    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)" >> "$etcconf"
                    echo "    RewriteRule .* - [F]" >> "$etcconf"
                    echo "    RewriteRule /management/other/ca.cert.der$ - [L]" >> "$etcconf"
                    echo "    RewriteCond %{HTTPS} off" >> "$etcconf"
                    echo "    RewriteRule (.*) https://%{HTTP_HOST}/\$1 [R,L]" >> "$etcconf"
                    echo "</VirtualHost>" >> "$etcconf"
                    echo "<VirtualHost *:443>" >> "$etcconf"
                    echo "    KeepAlive Off" >> "$etcconf"
                    echo "    <FilesMatch \"\.php\$\">" >> "$etcconf"
                    if [[ $osid -eq 1 && $OSVersion -lt 7 ]]; then
                        echo "        SetHandler application/x-httpd-php" >> "$etcconf"
                    else
                        echo "        SetHandler \"proxy:fcgi://127.0.0.1:9000/\"" >> "$etcconf"
                    fi
                    echo "    </FilesMatch>" >> "$etcconf"
                    echo "    ServerName $ipaddress" >> "$etcconf"
                    echo "    ServerAlias $hostname" >> "$etcconf"
                    echo "    DocumentRoot $docroot" >> "$etcconf"
                    echo "    SSLEngine On" >> "$etcconf"
                    echo "    SSLProtocol all -SSLv3 -SSLv2" >> "$etcconf"
                    echo "    SSLCipherSuite ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA" >> "$etcconf"
                    echo "    SSLHonorCipherOrder On" >> "$etcconf"
                    echo "    SSLCertificateFile $webdirdest/management/other/ssl/srvpublic.crt" >> "$etcconf"
                    echo "    SSLCertificateKeyFile $sslprivkey" >> "$etcconf"
                    echo "    SSLCACertificateFile $webdirdest/management/other/ca.cert.pem" >> "$etcconf"
                    echo "    <Directory $webdirdest>" >> "$etcconf"
                    echo "        DirectoryIndex index.php index.html index.htm" >> "$etcconf"
                    echo "    </Directory>" >> "$etcconf"
                    echo "    RewriteEngine On" >> "$etcconf"
                    echo "    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)" >> "$etcconf"
                    echo "    RewriteRule .* - [F]" >> "$etcconf"
                    echo "    RewriteCond %{DOCUMENT_ROOT}/%{REQUEST_FILENAME} !-f" >> "$etcconf"
                    echo "    RewriteCond %{DOCUMENT_ROOT}/%{REQUEST_FILENAME} !-d" >> "$etcconf"
                    echo "    RewriteRule ^/fog/(.*)$ /fog/api/index.php [QSA,L]" >> "$etcconf"
                    echo "</VirtualHost>" >> "$etcconf"
                else
                    echo "    KeepAlive Off" >> "$etcconf"
                    echo "    <Directory $webdirdest>" >> "$etcconf"
                    echo "        DirectoryIndex index.php index.html index.htm" >> "$etcconf"
                    echo "         Allowoverride all
                                   Order allow,deny
                                   Allow from all
                                   Require all granted" >> "$etcconf"
                    echo "    </Directory>" >> "$etcconf"
                    echo "    RewriteEngine On" >> "$etcconf"
                    echo "    RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)" >> "$etcconf"
                    echo "    RewriteRule .* - [F]" >> "$etcconf"
                    echo "    RewriteCond %{DOCUMENT_ROOT}/%{REQUEST_FILENAME} !-f" >> "$etcconf"
                    echo "    RewriteCond %{DOCUMENT_ROOT}/%{REQUEST_FILENAME} !-d" >> "$etcconf"
                    echo "    RewriteRule ^/fog/(.*)$ /fog/api/index.php [QSA,L]" >> "$etcconf"
                    echo "</VirtualHost>" >> "$etcconf"
                fi
                diffconfig "${etcconf}"
                errorStat $?
                ln -s $webdirdest $webdirdest/ >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                case $osid in
                    1)
                        phpfpmconf='/etc/php-fpm.d/www.conf';
                        ;;
                    2)
                        if [[ $php_ver == 5 ]]; then
                            phpfpmconf="/etc/php$php_ver/fpm/pool.d/www.conf"
                        else
                            phpfpmconf="/etc/php/$php_ver/fpm/pool.d/www.conf"
                        fi
                        ;;
                    3)
                        phpfpmconf='/etc/php/php-fpm.d/www.conf'
                        ;;
                esac
                if [[ -n $phpfpmconf ]]; then
                    sed -i 's/listen = .*/listen = 127.0.0.1:9000/g' $phpfpmconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    sed -i 's/^[;]pm\.max_requests = .*/pm.max_requests = 2000/g' $phpfpmconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    sed -i 's/^[;]php_admin_value\[memory_limit\] = .*/php_admin_value[memory_limit] = 256M/g' $phpfpmconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    sed -i 's/pm\.max_children = .*/pm.max_children = 50/g' $phpfpmconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    sed -i 's/pm\.min_spare_servers = .*/pm.min_spare_servers = 5/g' $phpfpmconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    sed -i 's/pm\.max_spare_servers = .*/pm.max_spare_servers = 10/g' $phpfpmconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    sed -i 's/pm\.start_servers = .*/pm.start_servers = 5/g' $phpfpmconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                fi
                if [[ $osid -eq 2 ]]; then
                    a2enmod $phpcmd >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    a2enmod proxy_fcgi setenvif >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    a2enmod rewrite >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    a2enmod ssl >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    a2ensite "001-fog" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    a2dissite "000-default" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                fi
            ;;
    esac
    dots "Starting and checking status of web services"
    service apache2 stop >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sleep 2
    service apache2 start >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sleep 2
    service $phpfpm stop >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sleep 2
    service $phpfpm start >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sleep 2
    service apache2 status >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    service $phpfpm status >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
    caCreated="yes"
}

configureHttpd() {
    dots "Stopping web service"
    service apache2 stop >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    service php-fpm${php_ver} stop >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
    dots "Setting up Apache and PHP files"
    if [[ ! -f $phpini ]]; then
        echo "Failed"
        echo "   ###########################################"
        echo "   #                                         #"
        echo "   #      PHP Failed to install properly     #"
        echo "   #                                         #"
        echo "   ###########################################"
        echo
        echo "   Could not find $phpini!"
        exit 1
    fi
    if [[ $osid -eq 3 ]]; then
        if [[ ! -f $httpdconf ]]; then
            echo "   Apache configs not found!"
            exit 1
        fi
        # Enable Event
        sed -i '/LoadModule mpm_event_module modules\/mod_mpm_event.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        # Disable prefork and worker
        sed -i '/LoadModule mpm_prefork_module modules\/mod_mpm_prefork.so/s/^/#/g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i '/LoadModule mpm_worker_module modules\/mod_mpm_worker.so/s/^/#/g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        # Enable proxy
        sed -i '/LoadModule proxy_html_module modules\/mod_proxy_html.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i '/LoadModule xml2enc_module modules\/mod_xml2enc.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i '/LoadModule proxy_module modules\/mod_proxy.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i '/LoadModule proxy_http_module modules\/mod_proxy_http.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i '/LoadModule proxy_fcgi_module modules\/mod_proxy_fcgi.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        # Enable socache
        sed -i '/LoadModule socache_shmcb_module modules\/mod_socache_shmcb.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        # Enable ssl
        sed -i '/LoadModule ssl_module modules\/mod_ssl.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        # Enable rewrite
        sed -i '/LoadModule rewrite_module modules\/mod_rewrite.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        # Enable our virtual host file for fog
        grep -q "^Include conf/extra/fog\.conf" $httpdconf || echo -e "# FOG Virtual Host\nListen 443\nInclude conf/extra/fog.conf" >>$httpdconf
        # Enable php extensions
        sed -i 's/;extension=bcmath/extension=bcmath/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=curl/extension=curl/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=ftp/extension=ftp/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=gd/extension=gd/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=gettext/extension=gettext/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=ldap/extension=ldap/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=mysqli/extension=mysqli/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=openssl/extension=openssl/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=pdo_mysql/extension=pdo_mysql/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=posix/extension=posix/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=sockets/extension=sockets/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/;extension=zip/extension=zip/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        sed -i 's/$open_basedir\ =/;open_basedir\ =/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    fi
    # Enable Event
    sed -i '/LoadModule mpm_event_module modules\/mod_mpm_event.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    # Disable prefork and worker
    sed -i '/LoadModule mpm_prefork_module modules\/mod_mpm_prefork.so/s/^/#/g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i '/LoadModule mpm_worker_module modules\/mod_mpm_worker.so/s/^/#/g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    # Enable rewrite
    sed -i '/LoadModule rewrite_module modules\/mod_rewrite.so/s/^#//g' $httpdconf >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/post_max_size\ \=\ 8M/post_max_size\ \=\ 3000M/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/upload_max_filesize\ \=\ 2M/upload_max_filesize\ \=\ 3000M/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/.*max_input_vars\ \=.*$/max_input_vars\ \=\ 250000/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    # Enable php extensions
    sed -i 's/;extension=bcmath/extension=bcmath/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=curl/extension=curl/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=ftp/extension=ftp/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=gd/extension=gd/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=gettext/extension=gettext/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=ldap/extension=ldap/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=mysqli/extension=mysqli/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=openssl/extension=openssl/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=pdo_mysql/extension=pdo_mysql/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=posix/extension=posix/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=sockets/extension=sockets/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/;extension=zip/extension=zip/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sed -i 's/$open_basedir\ =/;open_basedir\ =/g' $phpini >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
    dots "Testing and removing symbolic links if found"
    if [[ -h ${docroot}fog ]]; then
        rm -f ${docroot}fog >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    fi
    if [[ -h ${docroot}${webroot} ]]; then
        rm -f ${docroot}${webroot} >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    fi
    errorStat $?
    dots "Backing up old data"
    if [[ -d $backupPath/fog_web_${version}.BACKUP ]]; then
        rm -rf $backupPath/fog_web_${version}.BACKUP >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    fi
    if [[ -d $webdirdest ]]; then
        cp -RT "$webdirdest" "${backupPath}/fog_web_${version}.BACKUP" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        rm -rf ${backupPath}/fog_web_${version}.BACKUP/lib/plugins/accesscontrol
        rm -rf "$webdirdest" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    fi
    if [[ $osid -eq 2 ]]; then
        if [[ -d ${docroot}fog ]]; then
            rm -rf ${docroot} >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        fi
    fi
    mkdir -p "$webdirdest" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    if [[ -d $docroot && ! -h ${docroot}fog ]] || [[ ! -d ${docroot}fog ]]; then
        ln -s $webdirdest  ${docroot}/fog >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    fi
    errorStat $?
    if [[ $copybackold -gt 0 ]]; then
        if [[ -d ${backupPath}/fog_web_${version}.BACKUP ]]; then
            dots "Copying back old web folder as is";
            cp -Rf ${backupPath}/fog_web_${version}.BACKUP/* $webdirdest/
            errorStat $?
            dots "Ensuring all classes are lowercased"
            for i in $(find $webdirdest -type f -name "*[A-Z]*\.class\.php" -o -name "*[A-Z]*\.event\.php" -o -name "*[A-Z]*\.hook\.php" 2>>$workingdir/error_logs/fog_error_${version}.log); do
                mv "$i" "$(echo $i | tr A-Z a-z)" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
            done
            errorStat $?
        fi
    fi
    dots "Copying new files to web folder"
    cp -Rf $webdirsrc/* $webdirdest/
    errorStat $?
    for i in $(find $backupPath/fog_web_${version}.BACKUP/management/other/ -maxdepth 1 -type f -not -name gpl-3.0.txt -a -not -name index.php -a -not -name 'ca.*' 2>>$workingdir/error_logs/fog_error_${version}.log); do
        cp -Rf $i ${webdirdest}/management/other/ >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    done
    if [[ $installlang -eq 1 ]]; then
        dots "Creating the language binaries"
        langpath="${webdirdest}/management/languages"
        languagesfound=$(find $langpath -maxdepth 1 -type d -exec basename {} \; | awk -F. '/\./ {print $1}' 2>>$workingdir/error_logs/fog_error_${version}.log)
        languagemogen "$languagesfound" "$langpath"
        echo "Done"
    fi
    dots "Creating config file"
    phpescsnmysqlpass="${snmysqlpass//\\/\\\\}";   # Replace every \ with \\ ...
    phpescsnmysqlpass="${phpescsnmysqlpass//\'/\\\'}"   # and then every ' with \' for full PHP escaping
    echo "<?php
/**
 * The main configuration FOG uses.
 *
 * PHP Version 5
 *
 * Constructs the configuration we need to run FOG.
 *
 * @category Config
 * @package  FOGProject
 * @author   Tom Elliott <tommygunsster@gmail.com>
 * @license  http://opensource.org/licenses/gpl-3.0 GPLv3
 * @link     https://fogproject.org
 */
/**
 * The main configuration FOG uses.
 *
 * @category Config
 * @package  FOGProject
 * @author   Tom Elliott <tommygunsster@gmail.com>
 * @license  http://opensource.org/licenses/gpl-3.0 GPLv3
 * @link     https://fogproject.org
 */
class Config
{
    /**
     * Calls the required functions to define items
     *
     * @return void
     */
    public function __construct()
    {
        global \$node;
        self::_dbSettings();
        self::_svcSetting();
        if (\$node == 'schema') {
            self::_initSetting();
        }
    }
    /**
     * Defines the database settings for FOG
     *
     * @return void
     */
    private static function _dbSettings()
    {
        define('DATABASE_TYPE', 'mysql'); // mysql or oracle
        define('DATABASE_HOST', '$snmysqlhost');
        define('DATABASE_NAME', '$mysqldbname');
        define('DATABASE_USERNAME', '$snmysqluser');
        define('DATABASE_PASSWORD', '$phpescsnmysqlpass');
    }
    /**
     * Defines the service settings
     *
     * @return void
     */
    private static function _svcSetting()
    {
        define('UDPSENDERPATH', '/usr/local/sbin/udp-sender');
        define('MULTICASTINTERFACE', '${interface}');
        define('UDPSENDER_MAXWAIT', null);
    }
    /**
     * Initial values if fresh install are set here
     * NOTE: These values are only used on initial
     * installation to set the database values.
     * If this is an upgrade, they do not change
     * the values within the Database.
     * Please use FOG Configuration->FOG Settings
     * to change these values after everything is
     * setup.
     *
     * @return void
     */
    private static function _initSetting()
    {
        define('TFTP_HOST', \"${ipaddress}\");
        define('TFTP_FTP_USERNAME', \"${username}\");
        define(
            'TFTP_FTP_PASSWORD',
            \"${password}\"
        );
        define('TFTP_PXE_KERNEL_DIR', \"${webdirdest}/service/ipxe/\");
        define('PXE_KERNEL', 'bzImage');
        define('PXE_KERNEL_RAMDISK', 275000);
        define('USE_SLOPPY_NAME_LOOKUPS', true);
        define('MEMTEST_KERNEL', 'memtest.bin');
        define('PXE_IMAGE', 'init.xz');
        define('STORAGE_HOST', \"${ipaddress}\");
        define('STORAGE_FTP_USERNAME', \"${username}\");
        define(
            'STORAGE_FTP_PASSWORD',
            \"${password}\"
        );
        define('STORAGE_DATADIR', '${storageLocation}/');
        define('STORAGE_DATADIR_CAPTURE', '${storageLocationCapture}');
        define('STORAGE_BANDWIDTHPATH', '${webroot}status/bandwidth.php');
        define('STORAGE_INTERFACE', '${interface}');
        define('CAPTURERESIZEPCT', 5);
        define('WEB_HOST', \"${ipaddress}\");
        define('WOL_HOST', \"${ipaddress}\");
        define('WOL_PATH', '/${webroot}wol/wol.php');
        define('WOL_INTERFACE', \"${interface}\");
        define('SNAPINDIR', \"${snapindir}/\");
        define('QUEUESIZE', '10');
        define('CHECKIN_TIMEOUT', 600);
        define('USER_MINPASSLENGTH', 4);
        define('NFS_ETH_MONITOR', \"${interface}\");
        define('UDPCAST_INTERFACE', \"${interface}\");
        // Must be an even number! recommended between 49152 to 65535
        define('UDPCAST_STARTINGPORT', 63100);
        define('FOG_MULTICAST_MAX_SESSIONS', 64);
        define('FOG_JPGRAPH_VERSION', '2.3');
        define('FOG_REPORT_DIR', './reports/');
        define('FOG_CAPTUREIGNOREPAGEHIBER', true);
        define('FOG_THEME', 'default/fog.css');
    }
}" > "${webdirdest}/lib/fog/config.class.php"
    errorStat $?
    dots "Creating redirection index file"
    if [[ ! -f ${docroot}/index.php ]]; then
        echo "<?php
header('Location: /fog/index.php');
die();
?>" > ${docroot}/index.php && chown ${apacheuser}:${apacheuser} ${docroot}/index.php
        errorStat $?
    else
        echo "Skipped"
    fi
    downloadfiles
    if [[ $osid -eq 2 ]]; then
        php -m | grep mysqlnd >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        if [[ ! $? -eq 0 ]]; then
            ${phpcmd}enmod mysqlnd >>$workingdir/error_logs/fog_error_${version}.log 2>&1
            if [[ ! $? -eq 0 ]]; then
                if [[ -e /etc/php${php_ver}/conf.d/mysqlnd.ini ]]; then
                    cp -f "/etc/php${php_ver}/conf.d/mysqlnd.ini" "/etc/php${php_ver}/mods-available/php${php_ver}-mysqlnd.ini" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                    ${phpcmd}enmod mysqlnd >>$workingdir/error_logs/fog_error_${version}.log 2>&1
                fi
            fi
        fi
    fi
    dots "Enabling apache and fpm services on boot"
    rc-update add apache2 >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    rc-update add php-fpm${php_ver} >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
    createSSLCA
    dots "Changing permissions on apache log files"
    chmod +rx $apachelogdir
    chmod +rx $apacheerrlog
    chmod +rx $apacheacclog
    chown -R ${apacheuser}:${apacheuser} $webdirdest
    errorStat $?
    [[ -d /var/www/html/ && ! -e /var/www/html/fog/ ]] && ln -s "$webdirdest" /var/www/html/
    [[ -d /var/www/ && ! -e /var/www/fog ]] && ln -s "$webdirdest" /var/www/
    chown -R ${apacheuser}:${apacheuser} "$webdirdest"
    chown -R ${username}:${apacheuser} "$webdirdest/service/ipxe"
}

configureTFTPandPXE() {
    [[ -d ${tftpdirdst}.prev ]] && rm -rf ${tftpdirdst}.prev >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    [[ ! -d ${tftpdirdst} ]] && mkdir -p $tftpdirdst >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    [[ -e ${tftpdirdst}.fogbackup ]] && rm -rf ${tftpdirdst}.fogbackup >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    [[ -d $tftpdirdst && ! -d ${tftpdirdst}.prev ]] && mkdir -p ${tftpdirdst}.prev >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    [[ -d ${tftpdirdst}.prev ]] && cp -Rf $tftpdirdst/* ${tftpdirdst}.prev/ >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    if [[ "x$httpproto" = "xhttps" ]]; then
        dots "Compiling iPXE binaries trusting your SSL certificate"
        cd $buildipxesrc
        ./buildipxe.sh ${sslpath}CA/.fogCA.pem >>$workingdir/error_logs/fog_ipxe-build_${version}.log 2>&1
        errorStat $?
        cd $workingdir
    fi
    dots "Setting up and starting TFTP and PXE Servers"
    cd $tftpdirsrc
    find -type d -exec mkdir -p /tftpboot/{} \; >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    find -type f -exec cp -Rfv {} $tftpdirdst/{} \; >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    cd $workingdir
    chown -R $username $tftpdirdst >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    chown -R $username $webdirdest/service/ipxe >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    find $tftpdirdst -type d -exec chmod 755 {} \; >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    find $webdirdest -type d -exec chmod 755 {} \; >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    find $tftpdirdst ! -type d -exec chmod 655 {} \; >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    configureDefaultiPXEfile
    service in.tftpd stop >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sleep 2
    service in.tftpd start >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
}

configureFTP() {
    dots "Setting up and starting VSFTP Server..."
    vsftp=$(vsftpd -version 0>&1 | awk -F'version ' '{print $2}')
    vsvermaj=$(echo $vsftp | awk -F. '{print $1}')
    vsverbug=$(echo $vsftp | awk -F. '{print $3}')
    seccompsand=""
    allow_writeable_chroot=""
    if [[ $vsvermaj -gt 3 ]] || [[ $vsvermaj -eq 3 && $vsverbug -ge 2 ]]; then
        seccompsand="seccomp_sandbox=NO"
    fi
    mv -fv "${ftpconfig}" "${ftpconfig}.${timestamp}" >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    echo -e  "max_per_ip=200\nanonymous_enable=NO\nlocal_enable=YES\nwrite_enable=YES\nlocal_umask=022\ndirmessage_enable=YES\nxferlog_enable=YES\nconnect_from_port_20=YES\nxferlog_std_format=YES\nlisten=YES\npam_service_name=vsftpd\nuserlist_enable=NO\n$seccompsand" > "$ftpconfig"
    diffconfig "${ftpconfig}"
    service vsftpd stop >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sleep 2
    service vsftpd start >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    sleep 2
    service vsftpd status >>$workingdir/error_logs/fog_error_${version}.log 2>&1
    errorStat $?
}

enableInitScript() {
    for serviceItem in $serviceList; do
        chmod +x $initdpath/$serviceItem >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        errorStat $?
        dots "Enabling $serviceItem Service"
        rc-update add $serviceItem >>$workingdir/error_logs/fog_error_${version}.log 2>&1
        errorStat $?
    done
}