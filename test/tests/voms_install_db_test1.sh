#!/bin/sh

function test_setup()
{
    TEST_NAME="voms_install_db fails correctly (1)"
    mkdir -p $1/tmp
    cert_setup $1
    if test $? -ne 0; then
        COMMENT="Cannot initialize certificates."
        return 1;
    fi
    export CERTDIR=$X509_CERT_DIR

    $1/libexec/voms/voms_install_db --vo $VONAME --port=$VOPORT \
        --db-admin=$DBROOT --db-pwd=$DBPWD --db=$VONAME --voms-name=$VONAME
    if test $? -ne 0 ; then
        return 0 ;
    else
        COMMENT="Returned 0 when should have failed."
        return 1;
    fi
}

function test_run()
{
    return 0;
}

function test_clean()
{
   rm -rf $1/etc/voms/testvo
   rm -rf $1/var/log/voms.$VONAME
    echo "DROP DATABASE IF EXISTS $VONAME;" | mysql -u$DBROOT -p$DBPWD
}