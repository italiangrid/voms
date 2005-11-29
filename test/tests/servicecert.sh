#!/bin/sh

function test_setup()
{
    TEST_NAME="using service certificate"
    mkdir -p $1/tmp
    cert_setup $1 "" ""  "/C=IT/CN=http\/TESTCERT"
    if test $? -ne 0; then
        COMMENT="Cannot initialize certificates."
        return 1;
    fi

    export CERTDIR=$X509_CERT_DIR
    $1/libexec/voms/voms_install_db --db-type=mysql --vo $VONAME --port=$VOPORT \
        --db-admin=$DBROOT --db-pwd=$DBPWD --db=$VONAME --sqlloc=$1/lib/libvomsmysql.so \
        --voms-name=$VONAME
    if test $? -ne 0 ; then
        COMMENT="Cannot install voms."
        return 1 ;
    fi

    if test -f $1/etc/voms/$VONAME/voms.conf; then
        echo ;
    else
        COMMENT="Cannot find voms.conf file."
        return 1;
    fi

    cat >$1/tmp/dump.sql <<EOF
-- INSERT INTO ca VALUES(6,'/C=IT/O=TEST CA', 'test CA');
-- INSERT INTO groups VALUES (1, '/$VONAME', 0, 1, 2, 1, 0, 1);
INSERT INTO usr VALUES(1, '/C=IT/CN=USER TEST CERT', 6, '', '', NULL, 0, 0);
INSERT INTO m VALUES(1, 1, NULL, NULL, 0, 0, 0 ,0);
EOF
    mysql -u$DBROOT -p$DBPWD -D$VONAME <$1/tmp/dump.sql
    if test $? -ne 0; then
        COMMENT="Could not initialize db."
        return 1;
    fi

    mkdir -p $1/.glite
    cat >$1/.glite/vomses <<EOF
"$VONAME" "`hostname`" "$VOPORT" "/C=IT/CN=http/TESTCERT" "$VONAME"
EOF
    cat >>$1/etc/voms/$VONAME/voms.conf <<EOF
--x509_cert_dir=$X509_CERT_DIR
--x509_user_cert=$1/etc/grid-security/hostcert.pem
--x509_user_key=$1/etc/grid-security/hostkey.pem
EOF
    chmod 644 $1/.glite/vomses
    chmod 755 $1/.glite
    killall edg-voms

    return 0

}

function test_run()
{
    $1/sbin/edg-voms --conf $1/etc/voms/$VONAME/voms.conf
    if test $? -ne 0; then
        COMMENT="could not start server"
        return 1;
    fi

    $1/bin/voms-proxy-init --userconf $1/.glite/vomses --voms $VONAME
    if test $? -ne 0; then
        COMMENT="Cannor run voms-proxy-init"
        return 1;
    fi
    ID=`id -u`
    FILE="`echo /tmp/x509up_u$ID`"

}

function test_clean()
{
   rm -rf $1/etc/voms/$VONAME
   rm -rf $1/var/log/voms.$VONAME
   killall edg-voms
   echo "DROP DATABASE IF EXISTS $VONAME;" | mysql -u$DBROOT -p$DBPWD
}