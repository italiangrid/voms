#!/bin/sh

function command()
{
    $@ >/dev/null 2>&1
}

function apushd()
{
    pushd $@ >/dev/null 2>&1
}

function apopd()
{
    popd >/dev/null 2>&1
}

function find_component()
{
    apushd .
    if test -d ../../$1; then
        cd ../../$1 &&
        ./configure && 
        make dist && 
        cp *.tar.gz $2
    elif test -d ../../org.glite.security.$1; then
        cd ../../org.glite.security.$1 &&
        ./configure &&
        make dist &&
        cp *.tar.gz $2
    else
        mkdir $2/tmp && 
        cd $2/tmp &&
        cvs -d :pserver:anonymous@infnforge.cnaf.infn.it:/cvsroot co $1 &&
        COMMENT="Had to get component from the development CVS" &&
        cd $2/tmp/$1 && 
        ./configure && 
        make dist && 
        cp *.tar.gz ../.. &&
        rm -rf $2/tmp
    fi
    apopd
}

function compile()
{
    apushd .
    cd $2

    if test -f $1-[0-9]*.tar.gz; then
        mkdir ttt &&
        cd ttt &&
        tar xzf ../$1-[0-9]*.tar.gz &&
        cd *
    elif test -f glite-security-$1-*.tar.gz; then
        mkdir ttt &&
        cd ttt &&
        tar xzf ../glite-security-$1-*.tar.gz &&
        cd *
    else
        apopd
        COMMENT="Unable to find tarball."
        return 1;
    fi

    ./configure --prefix=$2 --with-debug && make install && cd ../.. && rm -rf ttt
    res=$?
    apopd
    return $res
}

function ca_make_config()
{
    CVAL=`echo  "$2"|tr '/' '\\\\'|sed 's/\\\\\\\\/\\//' |tr '\\\\' '\\n'|grep  "^C="  | sed 's/C=//'` &&
    OVAL=`echo  "$2"|tr '/' '\\\\'|sed 's/\\\\\\\\/\\//' |tr '\\\\' '\\n'|grep  "^O="  | sed 's/O=//'` &&
    OUVAL=`echo "$2"|tr '/' '\\\\'|sed 's/\\\\\\\\/\\//' |tr '\\\\' '\\n'|grep  "^OU=" | sed 's/OU=//'` &&
    LVAL=`echo  "$2"|tr '/' '\\\\'|sed 's/\\\\\\\\/\\//' |tr '\\\\' '\\n'|grep  "^L="  | sed 's/L=//'` &&
    CNVAL=`echo "$2"|tr '/' '\\\\'|sed 's/\\\\\\\\/\\//' |tr '\\\\' '\\n'|grep  "^CN=" | sed 's/CN=//'` &&
    EVAL=`echo  "$2"|tr '/' '\\\\'|sed 's/\\\\\\\\/\\//' |tr '\\\\' '\\n'|grep  "^Email="  | sed 's/Email=//'` &&
    STVAL=`echo "$2"|tr '/' '\\\\'|sed 's/\\\\\\\\/\\//' |tr '\\\\' '\\n'|grep  "^ST="  | sed 's/ST=//'` &&

    cat >$1/ca/openssl.cnf <<EOF
#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
#

HOME			= $1/install/ca.
RANDFILE		= \$ENV::HOME/.rnd

oid_section		= new_oids

[ new_oids ]

[ ca ]
default_ca	= CA_default		# The default ca section

[ CA_default ]

dir		= ./     		  # Where everything is kept
certs		= \$dir		          # Where the issued certs are kept
crl_dir		= \$dir		          # Where the issued crl are kept
database	= \$dir/index.txt	  # database index file.
new_certs_dir	= \$dir          	  # default place for new certs.

certificate	= \$dir/cacert.pem 	  # The CA certificate
serial		= \$dir/serial 		  # The current serial number
crl		= \$dir/crl.pem 		  # The current CRL
private_key	= \$dir/cacert.pem         # The private key
RANDFILE	= \$dir/private/.rand	  # private random number file

x509_extensions	= usr_cert		  # The extentions to add to the cert

name_opt 	= ca_default		  # Subject Name options
cert_opt 	= ca_default		  # Certificate field options

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= md5			# which md to use.
preserve	= no			# keep passed DN ordering
policy		= policy_anything

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ req ]
default_bits		= 1024
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
#attributes		= req_attributes
x509_extensions	= v3_ca	# The extentions to add to the self signed cert

string_mask = nombstr

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= $CVAL
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= $STVAL

localityName			= Locality Name (eg, city)
localityName_default		= $LVAL

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= $OVAL

organizationalUnitName		= Organizational Unit Name (eg, section)
organizationalUnitName_default=$OUVAL

commonName			= Common Name (eg, your name or your server\'s hostname)
commonName_default = $CNVAL
commonName_max			= 64

emailAddress			= Email Address
emailAddress_default = $EVAL
emailAddress_max		= 64

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]

basicConstraints=CA:FALSE

nsComment			= "OpenSSL Generated Certificate"

subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer:always

[ v3_req ]

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer:always

basicConstraints = CA:true

[ crl_ext ]

authorityKeyIdentifier=keyid:always,issuer:always
EOF

}


function ca_config_setup()
{
    apushd .
    cd $1
    rm -rf $1/ca
    mkdir -p $1/ca
    ca_make_config $1
    apopd
}

function ca_interpret_subj()
{
    apushd .
    cd $1
    mkdir -p $1/ca
    ca_make_config $1 "$2"
    apopd
}

function cacert_create()
{
    apushd . 
    cd $1/ca &&
    mkdir -p $1/etc/grid-security/certificates &&
    touch index.txt &&
    echo "01" >serial &&
    ca_make_config $1 "$2" &&
    echo -e "\n\n\n\n\n\n" | openssl req -config $1/ca/openssl.cnf -new -x509 -nodes -days $3 -keyout cacert.pem -out cacert.pem &&
    hash=`openssl x509 -hash -noout -in cacert.pem` &&
    cp cacert.pem  $1/etc/grid-security/certificates/$hash.0 &&
    export X509_CERT_DIR=$1/etc/grid-security/certificates &&
    cat > $1/etc/grid-security/certificates/$hash.signing_policy <<EOF
access_id_CA       X509       '$2'
pos_rights         globus     CA:sign
cond_subjects      globus     '"*"'
EOF
    ret=$?
    apopd
    return $ret
}

function hostcert_create()
{
    apushd . 
    cd $1/ca &&
    mkdir -p $1/etc/grid-security &&
    ca_make_config $1 "$2" &&
    echo -e "\n\n\n\n\n\n" | openssl req -config $1/ca/openssl.cnf -new -nodes -out req.pem -keyout $1/etc/grid-security/hostkey.pem &&
    echo -e "y\ny\n" | openssl ca -config $1/ca/openssl.cnf -policy policy_anything -days $3 -out $1/etc/grid-security/hostcert.pem -in req.pem &&
    chmod 600 $1/etc/grid-security/hostkey.pem &&
    chmod 644 $1/etc/grid-security/hostcert.pem
    
    ret=$?
    apopd
    return $ret
}

function usercert_create()
{
    apushd . 
    cd $1/ca &&
    ca_make_config $1 "$2" &&
    echo -e "\n\n\n\n\n\n" | openssl req -config $1/ca/openssl.cnf -new -nodes -keyout req.pem -out req.pem &&
    echo -e "y\ny\n" | openssl ca -config $1/ca/openssl.cnf -policy policy_anything -days $3 -out $1/usercert.pem -in req.pem &&
    chmod 600 req.pem &&
    chmod 644 $1/usercert.pem &&
    mv req.pem $1/userkey.pem &&
    export X509_USER_CERT=$1/usercert.pem &&
    export X509_USER_KEY=$1/userkey.pem &&

    ret=$?
    apopd
    return $ret
}

function cert_setup()
{
    apushd .
    cd $1
    if test "x$2" = "x"; then
        casubj="/C=IT/O=TEST CA"
    else
        casubj="$2"
    fi

    if test "x$3" = "x"; then
        calen=3
    else
        calen=$3
    fi

    if test "x$4" = "x"; then
        hostsubj="/C=IT/CN=HOST TEST CERT"
    else
        hostsubj="$4"
    fi

    if test "x$5" = "x"; then
        hostlen=2
    else
        hostlen=$5
    fi

    if test "x$6" = "x"; then
        certsubj="/C=IT/CN=USER TEST CERT"
    else
        certsubj=$6
    fi

    if test "x$7" = "x"; then
        userlen=2
    else
        userlen=$7
    fi


    ca_config_setup $1 &&
    cacert_create $1 "$casubj" $calen &&
    hostcert_create $1 "$hostsubj" $hostlen &&
    usercert_create $1 "$certsubj" $userlen

    ret=$?
    apopd
    return $ret
}

function security_setup()
{
    apushd .
    export LD_LIBRARY_PATH="$1/lib:$LD_LIBRARY_PATH" &&
    export VOMS_PROXY_INIT="$1/bin/voms-proxy-init" &&
    export VOMS_PROXY_INFO="$1/bin/voms-proxy-info" &&
    export VOMS_PROXY_DESTROY="$1/bin/voms-proxy-destroy" &&
    export VOMS="$1/sbin/edg-voms" &&
    cd $1 && 
    mkdir -p etc/grid-security &&
    mkdir -p etc/grid-security/certificates &&
    mkdir -p etc/vomsdir &&
    mkdir -p ca &&
    cert_setup $1

    ret=$?
    apopd
    return $ret
}


dirname="/tmp/voms_test$$/"

if test "x$LOGDIR" = "x"; then
    filedir=/data/marotta
else
    filedir=$LOGDIR
fi

htmlout=$filedir/testout.html


if test "x$DBROOT" = "x"; then
    DBROOT="root"
fi

if test "x$DBPWD" = "x"; then
    DBPWD="pwd"
fi

function report_progress()
{
    RES=`tail -1 $htmlout | grep "<td align=\"left\" bgcolor=\"yellow\">in progress"`
    if test $? -eq 0; then
      num=$((`wc -l <$htmlout` -1 ))
      head -$num <$htmlout >$htmlout.tmp
      mv $htmlout.tmp $htmlout
    fi

    echo -n >>$htmlout "<tr><td align=\"left\">$NAME</td><td align=\"left\">$TEST_NAME</td><td align=\"left\" bgcolor=\""
    echo >>$htmlout "yellow\">in progress</td><td align=\"left\">$PERCENT</td><td></td></tr>"
}

function do_tests()
{
    apushd .
    cd tests
    for i in `ls -B *.sh` ; do
        if test -f $i; then
            apushd .
            COMMENT=""
            FILE=""
            NAME=$i
            OUTPUT=`mktemp $filedir/out-XXXXXX`
            VONAME=testvo$$
            VOPORT=$(( (20000 + $$) % 10000 + 20000))

            source $i
            
            test_setup $1 >$OUTPUT 2>&1 &&
            test_run   $1 >>$OUTPUT 2>&1 

            error=$?

            RES=`tail -1 $htmlout | grep "<td align=\"left\" bgcolor=\"yellow\">in progress"`
            if test $? -eq 0; then
                num=$((`wc -l <$htmlout` -1 ))
                head -$num <$htmlout >$htmlout.tmp
                mv $htmlout.tmp $htmlout
            fi

            if test $error -ne 0; then
                FILENAME=`basename $OUTPUT`
                echo -n >>$htmlout "<tr><td align=\"left\">$NAME</td><td align=\"left\">$TEST_NAME</td><td align=\"left\" bgcolor=\""
                echo -n >>$htmlout "red\">failed</td><td align=\"left\">$COMMENT</td><td><a href=\"./$FILENAME\">stdout</a> "
                chmod 644 $OUTPUT
            else
                echo -n >>$htmlout "<tr><td align=\"left\">$NAME</td><td align=\"left\">$TEST_NAME</td><td align=\"left\" bgcolor=\""
                echo -n >>$htmlout "green\">succeded</td><td align=\"left\">$COMMENT</td><td>"
                rm $OUTPUT
            fi
            for f in $FILE; do
                OUT=`mktemp $filedir/out-XXXXXX`
                FILENAME=`basename $OUT`
                cp $f $OUT
                chmod 644 $OUT
                echo -n >>$htmlout "<a href=\"./$FILENAME\">$f</a> "
            done
            echo >>$htmlout "</td></tr>"
            test_clean $1
            apopd
        fi
    done
    apopd
}

function do_test_func()
{
    apushd .

    COMMENT=""
    FILE=""
    OUTPUT=`mktemp $filedir/out-XXXXXX`
    COMMENT=""
    TEST_NAME="$@"

    eval $@ >$OUTPUT 2>&1

    if test $? -ne 0; then
        NAME=`basename $OUTPUT`
        echo -n >>$htmlout "<tr><td></td><td align=\"left\">$TEST_NAME</td><td align=\"left\" bgcolor=\""
        echo >>$htmlout "red\">failed</td><td align=\"left\">$COMMENT</td><td><a href=\"./$NAME\">stdout</a></td></tr>"
        chmod 644 $OUTPUT
    else
        echo -n >>$htmlout "<tr><td></td><td align=\"left\">$TEST_NAME</td><td align=\"left\" bgcolor=\""
        echo >>$htmlout "green\">succeded</td><td align=\"left\">$COMMENT</td><td></td></tr>"
        rm $OUTPUT
    fi

    apopd
}

function voms_add_ca()
{
    voname=$2
    cafile=$3
    value=0

    subject=`openssl x509 -subject -noout -in $cafile|cut -f2`
    dbname=`cat  $1/etc/voms/$voname/voms.conf|grep "--dbname"| cut -d'=' -f2`
    echo "insert into ca values(NULL, "$subject", "$subject")" |mysql -u$DBROOT -p$DBPWD -D$dbname &&
    value=`echo "select cid from ca where ca.ca="$subject"|mysql -u$DBROOT -p$DBPWD -D$dbname|tail -1`
    return $value
}

function voms_add_group()
{
    voname=$2
    groupname=$3
    value=0
    dbname=`cat  $1/etc/voms/$voname/voms.conf|grep "--dbname"| cut -d'=' -f2`
    echo "insert into groups values(NULL, "$groupname", 0, 1, 2, 1, 0, NULL)" |mysql -u$DBROOT -p$DBPWD -D$dbname &&
    value=`echo "select gid from groups where groups.dn="$groupname"|mysql -u$DBROOT -p$DBPWD -D$dbname|tail -1`
    return $value
}

function voms_add_role()
{
    voname=$2
    rolename=$3
    value=0
    dbname=`cat  $1/etc/voms/$voname/voms.conf|grep "--dbname"| cut -d'=' -f2`
    echo "insert into roles values(NULL, "$rolename", 0, 0, 0, NULL)" |mysql -u$DBROOT -p$DBPWD -D$dbname &&
    value=`echo "select rid from roles where roles.dn="$rolename"|mysql -u$DBROOT -p$DBPWD -D$dbname|tail -1`
    return $value
}

function voms_add_user()
{
    voname=$2
    usercert=$3
    value=0

    subject=`openssl x509 -subject -noout -in $usercert|cut -f2`
    issuer=`openssl x509 -issuer -noout -in $usercert|cut -f2`
    dbname=`cat  $1/etc/voms/$voname/voms.conf|grep "--dbname"| cut -d'=' -f2`
    
    echo "insert into roles values(NULL, "$rolename", 0, 0, 0, NULL)" |mysql -u$DBROOT -p$DBPWD -D$dbname &&
    value=`echo "select rid from roles where roles.dn="$rolename"|mysql -u$DBROOT -p$DBPWD -D$dbname|tail -1`
    return $value
}
    
function voms_setup()
{
    mkdir -p $1/tmp
    export CERTDIR=$X509_CERT_DIR
    $1/libexec/voms/voms_install_db --db-type=mysql --vo testvo --port=20000 \
        --db-admin=$DBROOT --db-pwd=$DBPWD --db=testdb --sqlloc=$1/lib/libvomsmysql.so \
        --loglevel 7

    if test $? -ne 0 ; then
        COMMENT="Cannot install voms."
        return 1 ;
    fi

    if test -f $1/etc/voms/testvo/voms.conf; then
        echo ;
    else
        COMMENT="Cannot find voms.conf file."
        return 1;
    fi

    voms_add_ca $1 testvo $CAFILE
    canum=$?
    if test $canum -eq 0; then
        COMMENT="Cannot setup VOMS Server."
        return 1;
    fi

    cat >$1/tmp/dump.sql <<EOF
-- INSERT INTO ca VALUES(6,'/C=IT/O=TEST CA', 'test CA');
-- INSERT INTO groups VALUES (1, '/testvo', 0, 1, 2, 1, 0, 1);
INSERT INTO usr VALUES(1, '/C=IT/CN=USER TEST CERT', 6, '', '', NULL, 0, 0);
INSERT INTO m VALUES(1, 1, NULL, NULL, 0, 0, 0 ,0);
EOF
    mysql -u$DBROOT -p$DBPWD -Dtestdb <$1/tmp/dump.sql
    if test $? -ne 0; then
        COMMENT="Could not initialize db."
        return 1;
    fi

    mkdir -p $1/.glite
    cat >$1/.glite/vomses <<EOF
"testvo" "`hostname`" "20000" "`openssl x509 -subject -noout -in $1/etc/grid-security/hostcert.pem | cut -d' ' -f 2-`" "testvo"
EOF
    cat >>$1/etc/voms/testvo/voms.conf <<EOF
--x509_cert_dir=$X509_CERT_DIR
--x509_user_cert=$1/etc/grid-security/hostcert.pem
--x509_user_key=$1/etc/grid-security/hostkey.pem
EOF
    chmod 644 $1/.glite/vomses
    chmod 755 $1/.glite
    killall edg-voms

    return 0;

}

function start()
{
    rm -f $filedir/out-*
    rm -f $htmlout

    cat >$htmlout <<EOF
<html>
<head><title>Test results on: `hostname` running `cat /etc/issue`</title></head>
<body>
<h1>Test results on: `hostname` running `cat /etc/issue` on `date`</h3>
<table style="width: 100%;" border="1"><d>
<tr>
<th align="left">test file</th>
<th align="left">test name</th>
<th align="left">result</th>
<th align="left">comment</th>
<th align="left">artifacts</th>
EOF

    chmod 644 $htmlout
    if test "x$INSTALLDIR" = "x"; then
        rm -rf $dirname
        mkdir -p $dirname

        do_test_func find_component voms-mysql         $dirname
        do_test_func find_component voms-oracle        $dirname
        do_test_func find_component voms               $dirname
        do_test_func compile        voms               $dirname
        do_test_func compile        voms-mysql-plugin  $dirname
        do_test_func compile        voms-oracle        $dirname
    else
        dirname=$INSTALLDIR
    fi

    do_test_func security_setup                    $dirname

    do_tests                   $dirname
    echo >>$htmlout "</table></body></html>"

    if test "x$INSTALLDIR" = "x"; then
        if test "x$LEAVE" = "x"; then
            rm -rf $dirname
        fi
    fi
}