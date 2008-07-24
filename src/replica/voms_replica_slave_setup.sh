#!/bin/bash
#
# Default prefix

CERTDIR=${CERTDIR:-/etc/grid-security/certificates} #CERTDIR
SSLPROG="openssl"                                   #openssl
MYSQL_HOME=/usr                                     # MySQL install prefi
master_host=""                                      # Master
mysql_username_admin="replica"                      # Master MySQL admin user
mysql_password_admin=""                             # Master MySQL admin pass 
master_log_file=""                                  # Master LOG file
master_log_pos=""                                   # Master LOG file
mysql_username_admin="root"                         # MySQL admin username
mysql_password_admin=""                             # MySQL admin pass
mysql_replica_user="replica"                        # user for replication
mysql_conf_file="/etc/my.cnf"
ssl_capath="/etc/grid-security/certificates"
ssl_mysqlcert="/etc/grid-security/mysqlcert.pem"
ssl_mysqlkey="/etc/grid-security/mysqlkey.pem"
slaveid="2"
verbose=""
force="n"                                           # avoid asking questions
dryrun="n"
use_ssl="n"

TEMP=`getopt -o hv --long help,force,mysql-conf-file:,mysql-home:,slave-id:,mysql-admin:,mysql-pwd:,replica-user:,replica-user-pwd:,master-host:,log-file:,log-file-position:,master-db:,ssl-capath:,ssl-mysqlcert:,ssl-mysqlkey:,master-host:,use-ssl,help,ignore:,verbose  -n 'voms_install_replica' -- "$@"`

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
	--master-host)            master_host=$2             ; shift 2 ;;
  --mysql-conf-file)        mysql_conf_file=$2         ; shift 2 ;;
	--master-db)              master_db=$2               ; shift 2 ;;
  --ssl-capath)             ssl_capath=$2              ; shift 2 ;;
  --ssl-mysqlcert)          ssl_mysqlcert=$2           ; shift 2 ;;
  --ssl-mysqlkey)           ssl_mysqlkey=$2            ; shift 2 ;;           
  --use-ssl)                require_ssl="y"                ; shift   ;;
  --log-file)               log_file=$2                ; shift 2 ;;
  --log-file-position)      log_file_pos=$2            ; shift 2 ;;
  --ignore)                 ignore_tables=$2           ; shift 2 ;;
  --dry-run)                dryrun="y"                 ; shift   ;;
  --slave-id)               slaveid=$2                 ; shift 2 ;;
	-v)                       verbose="1"                ; shift   ;;
	--verbose)                verbose="1"                ; shift   ;;
  -h)                       help="yes"                 ; shift   ;;
  --help)                   help="yes"                 ; shift   ;;
	--)                       shift                      ; break   ;;
	*)                        echo "Unknown Option:$1" >&2 ; exit 1  ;;
    esac
done

if test "x$help" = "xyes" ; then
    $ECHO "USAGE: voms-replica-slave-setup.sh [--option value] ... [--option value]"
    $ECHO ""
    $ECHO "Where --option may be:"
    $ECHO "   --mysql-home <path>       Where the MySQL installation is based."
    $ECHO "                             Defaults to \$MYSQL_HOME if set, otherwise"
    $ECHO "                             assumes that the executables can be"
    $ECHO "                             found in \$PATH"
    $ECHO "   --force                   Skips the initial warning."
    $ECHO "   --mysql-admin <name>      The MySQL Admin account. Defaults to 'root'"
    $ECHO "   --mysql-pwd <password>    The password of the MySQL Admin account."
    $ECHO "                             Does not have a default."
    $ECHO "   --replica-user <name>     The user which will be setup for replication."
    $ECHO "                             Defaults to 'replica'"
    $ECHO "   --replica-user-pwd <pwd>  The password of the above account.  No defaults,"
    $ECHO "                             this MUST be specified."
    $ECHO "   --master-host <hostname>  The fully qualified hostname to which the"
    $ECHO "                             replica will connect."
    $ECHO "   --mysql-conf-file <path>  The location of the MySQL configuration file."
    $ECHO "                             Defaults to /etc/my.cnf"
    $ECHO "   --master-db <dbname>      The name of the DB to replicate. No defaults."            
    $ECHO "                             MUST be specified."
    $ECHO "   --use-ssl                 Activates the following three options, and"
    $ECHO "                             specifies a SSL connection for the replication."
    $ECHO "   --ssl-capath <path>       The location where the CA certificates will be found."
    $ECHO "                             Defaults to '/etc/grid-security/certificates'"
    $ECHO "   --ssl-mysqlcert <file>    The location where the host certificate for MySQL"
    $ECHO "                             will be found."
    $ECHO "                             Defaults to '/etc/grid-security/mysqlcert.pem'"
    $ECHO "   --ssl-mysqlkey <file>     The location where the key of the certificate will"
    $ECHO "                             be found.  Defaults to '/etc/grid-security/mysqlkey.pem"
    $ECHO "   --log-file <file>         Specifies the master's log file from which to"
    $ECHO "                             replicate transactions."
    $ECHO "   --log-file-position <pos> Specifies the position in the log file from which"
    $ECHO "                             to start replication."
    $ECHO "   --ignore <tables>         Comma-separated list of tables to ignore during"
    $ECHO "                             replication."
    $ECHO "   --dry-run                 Do not actually modify anything."
    $ECHO "  --slave-id <number>        Must be a number >=2, a different number for"
    $ECHO "                             slave. Defaults to 2."
    $ECHO "   -h, --help                This test"
    exit 0;
fi

if test "x$do_force" != "xy" ; then
    echo "WARNING: This script assumes that it can thrash the current server configuration"
    echo "If instead you wish to keep it, read the documentation and perform the procedure by hand."
    echo "Do you wish to continue?  type YES if it is so."
    read answer

    if test "z$answer" != "zYES" ; then
        exit 1;
    fi
fi


if test "x$mysql_replica_user_pwd" = "x" ; then
    echo "Did not specify the replication password.";
    exit 1;
fi

if test "x$log_file" = "x" ; then
    echo "Did not specify the mater log file name.";
    exit 1;
fi

if test "x$log_file_pos" = "x" ; then
    echo "Did not specify the mater log file position.";
    exit 1;
fi

if test "x$master_db" = "x" ; then 
    echo "Did not specify which db to replicate";
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

if test -e /etc/rc.d/init.d/mysqld ; then
    MYSQLINIT=/etc/rc.d/init.d/mysqld
elif test -e /etc/rc.d/init.d/mysql ; then
    MYSQLINIT=/etc/rc.d/init.d/mysql
fi


if test "x$dryrun" = "xn" ; then
    $MYSQLINIT stop

#GET MUST PRESERVE DATA

    set datadir=`cat $mysql_conf_file|grep 'datadir='`
    set socket=`cat $mysql_conf_file|grep 'socket='`
    set oldpass=`cat $mysql_conf_file|grep 'old_passwords='`
    set replicate=`cat $mysql_conf_file|grep 'replicate-do-db'`
    set ignore=`cat $mysql_conf_file|grep 'replicate-ignore-table'`
    cat >$mysql_conf_file <<EOF
[mysqld]
$datadir
$socket
# Default to using old password format for compatibility with mysql 3.x
# clients (those using the mysqlclient10 compatibility package).
$oldpass
log-bin
server-id=$slaveid
sync_binlog=1
#innodb-safe-binlog
EOF
if test "z$require_ssl" = "zy" ; then
    cat >>$mysql_conf_file <<EOF
ssl
ssl-capath=$ssl_capath
ssl-cert=$ssl_mysqlcert
ssl-key=$ssl_mysqlkey
EOF
fi

if test "x$replicate" = "x" ; then
    cat >>$mysql_conf_file <<EOF
replicate-do-db=$master_db
EOF
else
    cat >>$mysql_conf_file <<EOF
$replicate
replicate-do-db=$master_db
EOF
fi
    cat >>$mysql_conf_file <<EOF     
$ignore
EOF

if test "x$ignore_tables" != "x" ; then
    echo "$ignore_tables" | tr "," "\n" | tr -d " " | MAST=$master_db awk ' BEGIN { mst=ENVIRON["MAST"]; OFS="" } { print "replicate-ignore-table=", mst, ".", $1 }' >>$mysql_conf_file
fi

    cat >>$mysql_conf_file <<EOF     
[client]
$socket
ssl
ssl-capath=$ssl_capath
ssl-cert=$ssl_mysqlcert
ssl-key=$ssl_mysqlkey

EOF

    $MYSQLINIT start

fi

$MYSQL < $master_db.dump

if test "x$require_ssl" = "xy" ; then
    $MYSQL -e "STOP SLAVE; CHANGE MASTER TO MASTER_HOST='$master_host', MASTER_USER='$mysql_replica_user', MASTER_PASSWORD='$mysql_replica_user_pwd', MASTER_LOG_FILE='$log_file', MASTER_LOG_POS=$log_file_pos, MASTER_SSL=1, MASTER_SSL_CAPATH='$ssl_capath', MASTER_SSL_CERT='$ssl_mysqlcert', MASTER_SSL_KEY='$ssl_mysqlkey'; START SLAVE;"
else
    $MYSQL -e "STOP SLAVE; CHANGE MASTER TO MASTER_HOST='$master_host', MASTER_USER='$mysql_replica_user', MASTER_PASSWORD='$mysql_replica_user_pwd', MASTER_LOG_FILE='$log_file', MASTER_LOG_POS=$log_file_pos; START SLAVE;"
fi

$MYSQL -e "STOP SLAVE;"
$MYSQL -e "START SLAVE;"
