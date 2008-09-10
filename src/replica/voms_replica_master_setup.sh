#!/bin/bash
#
# Default prefix

CERTDIR=${CERTDIR:-/etc/grid-security/certificates} #CERTDIR
SSLPROG="openssl"                                   #openssl
MYSQL_HOME=/usr                                     # MySQL install prefi
voms_database="voms"                                # VOMS database
master_mysql_user="replica"                         # Master MySQL admin user
master_mysql_pwd=""                                 # Master MySQL admin pass 
master_log_file=""                                  # Master LOG file
master_log_pos=""                                   # Master LOG file
mysql_username_admin="root"                         # MySQL admin username
mysql_password_admin=""                             # MySQL admin pass
mysql_replica_user="replica"                        # user for replication
mysql_conf_file="/etc/my.cnf"
mysql_version=4
ssl_capath="/etc/grid-security/certificates"
ssl_mysqlcert="/etc/grid-security/mysqlcert.pem"
ssl_mysqlkey="/etc/grid-security/mysqlkey.pem"
verbose=""
force="n"                                           # avoid asking questions
dryrun="n"
require_ssl="n"
help="no"
TEMP=`getopt -o hv --long help,mysql-version:,force,mysql-conf-file:,mysql-home:,mysql-admin:,mysql-pwd:,replica-user:,replica-user-pwd:,master-db:,slave-host:,ssl-capath:,ssl-mysqlcert:,ssl-mysqlkey:,require-ssl,dry-run,verbose  -n 'voms_install_replica' -- "$@"`

ECHO=`which echo`

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"

while true ; do
    case "$1" in
	--mysql-home)             MYSQL_HOME=$2              ; shift 2 ;;
  --force)                  do_force="y"               ; shift   ;;
	--mysql-admin)            mysql_username_admin=$2    ; shift 2 ;;
	--mysql-pwd)              mysql_password_admin=$2    ; shift 2 ;;
  --replica-user)           mysql_replica_user=$2      ; shift 2 ;;
  --replica-user-pwd)       mysql_replica_user_pwd=$2  ; shift 2 ;;
	--slave-host)             slave_host=$2              ; shift 2 ;;
  --mysql-conf-file)        mysql_conf_file=$2         ; shift 2 ;;
	--master-db)              master_db=$2               ; shift 2 ;;
  --ssl-capath)             ssl_capath=$2              ; shift 2 ;;
  --ssl-mysqlcert)          ssl_mysqlcert=$2           ; shift 2 ;;
  --ssl-mysqlkey)           ssl_mysqlkey=$2            ; shift 2 ;;           
  --dry-run)                dryrun="y"                 ; shift   ;;
  --require-ssl)            require_ssl="y"            ; shift   ;;
  --mysql-version)          mysql_version="$2"         ; shift 2 ;;
	-v)                       verbose="1"                ; shift   ;;
	-verbose)                 verbose="1"                ; shift   ;;
  -h)                       help="yes"                 ; shift   ;;
  --help)                   help="yes"                 ; shift   ;;
	--)                       shift                      ; break   ;;
	*)                        echo "Unknown Option!" >&2 ; exit 1  ;;
    esac
done

if test "x$help" = "xyes" ; then
    $ECHO "USAGE: voms-replica-master-setup.sh [--option value] ... [--option value]"
    $ECHO
    $ECHO "Where --option may be:"
    $ECHO "   --mysql-home <path>      Where the MySQL installation is based."
    $ECHO "                            Defaults to \$MYSQL_HOME if set, otherwise"
    $ECHO "                            assumes that the executables can be"
    $ECHO "                            found in \$PATH"
    $ECHO "   --force                  Skips the initial warning."
    $ECHO "   --mysql-admin <name>     The MySQL Admin account. Defaults to 'root'"
    $ECHO "   --mysql-pwd <password>   The password of the MySQL Admin account."
    $ECHO "                            Does not have a default."
    $ECHO "   --replica-user <name>    The user which will be setup for replication."
    $ECHO "                            Defaults to 'replica'"
    $ECHO "   --replica-user-pwd <pwd> The password of the above account.  No defaults,"
    $ECHO "                            but one will be generated if not specified."
    $ECHO "   --slave-host <hostname>  The fully qualified hostname from which the"
    $ECHO "                            replica will connect."
    $ECHO "   --mysql-conf-file <path> The location of the MySQL configuration file."
    $ECHO "                            Defaults to /etc/my.cnf"
    $ECHO "   --master-db <dbname>     The name of the DB to replicate. No defaults."            
    $ECHO "                            MUST be specified."
    $ECHO "   --require-ssl            Activates the following three options, and"
    $ECHO "                            requires a SSL connection for the replication."
    $ECHO "   --ssl-capath <path>      The location where the CA certificates will be found."
    $ECHO "                            Defaults to '/etc/grid-security/certificates'"
    $ECHO "   --ssl-mysqlcert <file>   The location where the host certificate for MySQL"
    $ECHO "                            will be found."
    $ECHO "                            Defaults to '/etc/grid-security/mysqlcert.pem'"
    $ECHO "   --ssl-mysqlkey <file>    The location where the key of the certificate will"
    $ECHO "                            be found.  Defaults to '/etc/grid-security/mysqlkey.pem"
    $ECHO "   --dry-run                Do not actually modify anything."
    $ECHO "   --mysql-version <num>    Major version of mysql."
    $ECHO "   -h, --help               This test"
    $ECHO
    $ECHO "Note:  Due to a bug on some versions of MySQL 5, admin running those version"
    $ECHO "should either regenerate the dump file and overwrite that created by the script"
    $ECHO "or ensure that no other process updates the master-db during its creation."
    exit 0;
fi

if test "x$do_force" != "xy" ; then
    echo "WARNING: This script assumes that it can thrash the current server"
    echo "configuration.  If instead you wish to keep it, read the"
    echo "documentation and perform the procedure by hand."
    echo "Do you wish to continue?  type YES if it is so."
    read answer

    if test "z$answer" != "zYES" ; then
        echo "Operation aborted."
        exit 1;
    fi
fi


if test "x$mysql_replica_user_pwd" = "x" ; then
    mysql_replica_user_pwd="`$SSLPROG rand -base64 6`"
fi

if test "x$master_db" = "x" ; then
    echo "--master-db <dbname> MUST be specified."
    exit 1;
fi

###############################################################################
#CREATE USER

if test "x$dryrun" = "xy" ; then
    MYSQL=echo
elif test "x$mysql_password_admin" = "x" ; then
    MYSQL="$MYSQL_HOME/bin/mysql -u$mysql_username_admin"
else
    MYSQL="$MYSQL_HOME/bin/mysql -u$mysql_username_admin -p$mysql_password_admin"
fi

MYSQLDUMP=$MYSQL_HOME/bin/mysqldump
MYSQLINIT=/etc/rc.d/init.d/mysql

if test "x$require_ssl" = "xy" ; then
   $MYSQL -e "GRANT REPLICATION SLAVE ON *.* TO '$mysql_replica_user'@'$slave_host' IDENTIFIED BY '$mysql_replica_user_pwd' REQUIRE SSL; GRANT SELECT ON $master_db.* TO '$mysql_replica_user'@'$slave_host' IDENTIFIED BY '$mysql_replica_user_pwd' REQUIRE SSL; FLUSH PRIVILEGES;"
else
   $MYSQL -e "GRANT REPLICATION SLAVE ON *.* TO '$mysql_replica_user'@'$slave_host' IDENTIFIED BY '$mysql_replica_user_pwd' REQUIRE SSL; GRANT SELECT ON $master_db.* TO '$mysql_replica_user'@'$slave_host' IDENTIFIED BY '$mysql_replica_user_pwd'; FLUSH PRIVILEGES;"
fi

if test "x$mysql_version" = "x5" ; then
    if test "x$mysql_password_admin" = "x" ; then
        $MYSQLDUMP -u$mysql_username_admin -B $master_db >$master_db.dump
    else
        $MYSQLDUMP -u$mysql_username_admin -p$mysql_password_admin -B $master_db >$master_db.dump
    fi
else
if test "x$mysql_password_admin" = "x" ; then
    $MYSQL -e "FLUSH TABLES WITH READ LOCK; SHOW MASTER STATUS; SYSTEM $MYSQLDUMP -u$mysql_username_admin -B $master_db >$master_db.dump;" >/tmp/outfile
else
#GET REPLICATION DATA
$MYSQL -e "FLUSH TABLES WITH READ LOCK; SHOW MASTER STATUS; SYSTEM $MYSQLDUMP -u$mysql_username_admin -p$mysql_password_admin -B $master_db >$master_db.dump;" >/tmp/outfile
fi
fi

master_log_file=`cat /tmp/outfile | awk 'NR==2 {print $1}'`
master_log_pos=`cat /tmp/outfile  | awk 'NR==2 {print $2}'`

$MYSQL -e "USE $master_db; select * from seqnumber" 2>/dev/null >/dev/null

if test $? -eq 0 ; then
    ignoretables="seqnumber"
else
    ignoretables=""
fi

if test "x$dryrun" = "xn" ; then
    $MYSQLINIT stop

#GET MUST PRESERVE DATA

    set datadir=`cat $mysql_conf_file|grep 'datadir='`
    set socket=`cat $mysql_conf_file|grep 'socket='`
    set oldpass=`cat $mysql_conf_file|grep 'old_passwords='`
    cat >$mysql_conf_file <<EOF
[mysqld]
$datadir
$socket
# Default to using old password format for compatibility with mysql 3.x
# clients (those using the mysqlclient10 compatibility package).
$oldpass
log-bin
server-id=1
sync_binlog=1
EOF

if test "z$mysql_version" = "z4"; then
    cat >$mysql_conf_file <<EOF
innodb-safe-binlog
innodb_flush_log_at_trx_commit=1
EOF
fi

if test "z$require_ssl" = "zy" ; then
    cat >>$mysql_conf_file <<EOF
ssl
ssl-capath=$ssl_capath
ssl-cert=$ssl_mysqlcert
ssl-key=$ssl_mysqlkey
EOF
fi

    $MYSQLINIT start

fi

echo "Send these informations to the administrator of the slave server:"
echo "Log File    : $master_log_file"
echo "Log Position: $master_log_pos"
echo "Account name: $mysql_replica_user"
echo "Account pwd : $mysql_replica_user_pwd"
echo "DB name     : $master_db"
echo "Ignore      : $ignoretables"

echo "Also, send this file: $master_db.dump"

