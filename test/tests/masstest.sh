#! /bin/sh

function test_setup()
{
    TEST_NAME="VOMS stress test"
    mkdir -p $1/tmp
    touch $1/tmp/done
    touch $1/tmp/init_failure
    touch $1/tmp/info_failure
    touch $1/tmp/destroy_failure

    cert_setup $1
    if  test $? -ne 0; then
        COMMENT="Cannot initialize certificates."
        return 1;
    fi

    export CERTDIR=$X509_CERT_DIR
    $1/libexec/voms/voms_install_db --db-type=mysql --vo $VONAME --port=$VOPORT \
        --db-admin=$DBROOT --db-pwd=$DBPWD --db=$VONAME --sqlloc=$1/lib/libvomsmysql.so \
        --loglevel 5 --voms-name=$VONAME
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
"$VONAME" "`hostname`" "$VOPORT" "`openssl x509 -subject -noout -in $1/etc/grid-security/hostcert.pem | cut -d' ' -f 2-`" "$VONAME"
EOF
    cat >>$1/etc/voms/$VONAME/voms.conf <<EOF
--x509_cert_dir=$X509_CERT_DIR
--x509_user_cert=$1/etc/grid-security/hostcert.pem
--x509_user_key=$1/etc/grid-security/hostkey.pem
--backlog=200
EOF
    chmod 644 $1/.glite/vomses
    chmod 755 $1/.glite
    killall edg-voms

    return 0;
}

function test_run()
{
    $1/sbin/edg-voms --conf $1/etc/voms/$VONAME/voms.conf

    until grep "Trying to open socket" $1/var/log/voms.$VONAME; do
        sleep 1;
    done

    threads=10
    repeat=10
    n=2
    logfile=$1/tmp/logfile

    cat >> $1/tmp/script <<EOF
#! /bin/bash
let i=0
while test \$i -lt $repeat ; do
if ! $VOMS_PROXY_INIT --userconf $1/.glite/vomses --voms $VONAME -out $1/tmp/\$1\$2 &> $1/tmp/tmp_init_log\$1\$2; then
echo >> $1/tmp/init_failure
echo -e "Command : voms-proxy-init --userconf $1/.glite/vomses --voms $VONAME -out $1/tmp/\$1\$2" >> $logfile
cat $1/tmp/tmp_init_log\$1\$2 >> $logfile
echo >> $logfile
else
if ! $VOMS_PROXY_INFO -file $1/tmp/\$1\$2 &> $1/tmp/tmp_info_log\$1\$2; then
echo "" >> $1/tmp/info_failure
echo -e "Command : voms-proxy-info -file $1/tmp/\$1\$2" >> $logfile
cat $1/tmp/tmp_info_log\$1\$2 >> $logfile
echo >> $logfile
out=\$($VOMS_PROXY_INFO -fqan -file $1/tmp/\$1\$2)
fqan=/$VONAME/Role=NULL/Capability=NULL
elif test "x\$out" != "x\$fqan" ; then
echo -e "Command : voms-proxy-info -fqan -file $1/tmp/\$1\$2\n" >> $logfile
echo -e "Wrong attributes." >> $logfile
echo >> $logfile
fi
if ! $VOMS_PROXY_DESTROY -file $1/tmp/\$1\$2 &> $1/tmp/tmp_destroy_log\$1\$2; then
echo >> $1/tmp/destroy_failure
echo -e "Command : voms-proxy-destroy -file $1/tmp/\$1\$2" >> $logfile
cat $1/tmp/tmp_destroy_log\$1\$2 >> $logfile
echo >> $logfile
fi
fi
echo >> $1/tmp/done
let i=i+1
done
rm -f $1/tmp/tmp_init_log\$1\$2
rm -f $1/tmp/tmp_info_log\$1\$2
rm -f $1/tmp/tmp_destroy_log\$1\$2
EOF
    chmod 700 $1/tmp/script

    let i=0
    while test $i -lt $((threads)) ; do
        let j=$((n))
        while test $j -gt 0 ; do
            $1/tmp/script $i $j &
            let j=$j-1
        done
        let i=$i+1
    done

    while test $(wc -l < $1/tmp/done) != $((threads*repeat*n)) ; do
        PERCENT="Completion: $(wc -l < $1/tmp/done) out of $((threads*repeat*n))"
        report_progress
    done

    if test "`cat $1/tmp/init_failure $1/tmp/info_failure $1/tmp/destroy_failure| wc -l`" -ne "0"; then
        echo "$(($(wc -l < $1/tmp/done))) voms-proxy-init executed, $(wc -l < $1/tmp/init_failure) failed."
        echo "$(($(wc -l < $1/tmp/done))) voms-proxy-info executed, $(wc -l < $1/tmp/info_failure) failed."
        echo "$(($(wc -l < $1/tmp/done))) voms-proxy-destroy executed, $(wc -l < $1/tmp/destroy_failure) failed."
        echo "$(($(wc -l < $1/tmp/done))) voms-proxy-init executed, $(wc -l < $1/tmp/init_failure) failed." >> $logfile
        echo "$(($(wc -l < $1/tmp/done))) voms-proxy-info executed, $(wc -l < $1/tmp/info_failure) failed." >> $logfile
        echo "$(($(wc -l < $1/tmp/done))) voms-proxy-destroy executed, $(wc -l < $1/tmp/destroy_failure) failed." >> $logfile
        echo >> $logfile

        echo "DATABASE DUMP" >> $logfile
        mysqldump -B $VONAME -u$DBROOT -p$DBPWD >> $logfile
        FILE="$logfile $1/var/log/voms.$VONAME $1/tmp/script $1/tmp/init_failure"
        return 1;
    fi

    return 0;
}

function test_clean()
{
    rm -f $1/tmp/script
    rm -f $1/tmp/init_failure
    rm -f $1/tmp/info_failure
    rm -f $1/tmp/destroy_failure
    rm -f $1/tmp/done
    rm -f $1/tmp/logfile
    rm -rf $1/etc/voms/$VONAME
    rm -rf $1/var/log/voms.$VONAME
    killall edg-voms;
    echo "DROP DATABASE IF EXISTS $VONAME;" | mysql -u$DBROOT -p$DBPWD
}
