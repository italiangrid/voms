/*********************************************************************
 *
 * Authors: Valerio Venturi - Valerio.Venturi@cnaf.infn.it
 *          Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
 *
 * Copyright (c) 2002-2009 INFN-CNAF on behalf of the EU DataGrid
 * and EGEE I, II and III
 * For license conditions see LICENSE file or
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
/**********************************************************************

sslutils.c

Description:
        Routines used internally to implement delegation and proxy
        certificates for use with Globus The same file is also used
        for the non-exportable sslk5 which allows Kerberos V5 to
        accept SSLv3 with certificates as proof of identiy and
        issue a TGT.

**********************************************************************/

/**********************************************************************
                             Include header files
**********************************************************************/
#define _GNU_SOURCE

#include "config.h"
#include "replace.h"
#include "proxycertinfo.h"
#include "sslutils.h"
#include "parsertypes.h"
#include "doio.h"
#include "data.h"
#include "voms_cert_type.h"
#include "ssl_compat.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef DEFAULT_SECURE_TMP_DIR
#ifndef WIN32
#define DEFAULT_SECURE_TMP_DIR "/tmp"
#else
#define DEFAULT_SECURE_TMP_DIR "c:\\tmp"
#endif
#endif

#ifndef WIN32
#define FILE_SEPERATOR "/"
#else
#define FILE_SEPERATOR "\\"
#endif

#ifdef WIN32
#include "winglue.h"
#include <io.h>
#else
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>

#include "openssl/buffer.h"
#include "openssl/crypto.h"

#include "openssl/objects.h"
#include "openssl/asn1.h"
#include "openssl/evp.h"
#include "openssl/pkcs12.h"

#include "openssl/rsa.h"
#include "openssl/rand.h"
#if SSLEAY_VERSION_NUMBER >= 0x0090581fL
#include "openssl/x509v3.h"
#endif

#ifndef X509_V_ERR_INVALID_PURPOSE
#define X509_V_ERR_INVALID_PURPOSE X509_V_ERR_CERT_CHAIN_TOO_LONG
#endif

#ifdef USE_PKCS11
#include "scutils.h"
#endif

#include <assert.h>

static int fix_add_entry_asn1_set_param = 0;


#define V1_ROOT (EXFLAG_V1|EXFLAG_SS)
#define ku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_KUSAGE) && !((x)->ex_kusage & (usage)))
#define xku_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_XKUSAGE) && !((x)->ex_xkusage & (usage)))
#define ns_reject(x, usage) \
	(((x)->ex_flags & EXFLAG_NSCERT) && !((x)->ex_nscert & (usage)))

static X509_NAME *make_DN(const char *dnstring);


extern int restriction_evaluate(STACK_OF(X509) *chain, struct policy **namespaces,
                                struct policy **signings);
extern void voms_free_policies(struct policy **policies);
extern int read_pathrestriction(STACK_OF(X509) *chain, char *path,
                                struct policy ***namespaces,
                                struct policy ***signings);

static int check_critical_extensions(X509 *cert, int itsaproxy);

/**********************************************************************
                               Type definitions
**********************************************************************/


/**********************************************************************
                          Module specific prototypes
**********************************************************************/

/**********************************************************************
                       Define module specific variables
**********************************************************************/
static ERR_STRING_DATA prxyerr_str_functs[]=
{
    {ERR_PACK(0,PRXYERR_F_PROXY_GENREQ ,0),"proxy_genreq"},
    {ERR_PACK(0,PRXYERR_F_PROXY_SIGN ,0),"proxy_sign"},
    {ERR_PACK(0,PRXYERR_F_VERIFY_CB ,0),"proxy_verify_callback"},
    {ERR_PACK(0,PRXYERR_F_PROXY_TMP ,0),"proxy_marshal_tmp"},
    {ERR_PACK(0,PRXYERR_F_INIT_CRED ,0),"proxy_init_cred"},
    {ERR_PACK(0,PRXYERR_F_LOCAL_CREATE, 0),"proxy_local_create"},
    {ERR_PACK(0,PRXYERR_F_CB_NO_PW, 0),"proxy_pw_cb"},
    {ERR_PACK(0,PRXYERR_F_GET_CA_SIGN_PATH, 0),"get_ca_signing_policy_path"},
    {ERR_PACK(0,PRXYERR_F_PROXY_SIGN_EXT ,0),"proxy_sign_ext"},
    {ERR_PACK(0,PRXYERR_F_PROXY_VERIFY_NAME,0),
     "proxy_verify_name"},
    {ERR_PACK(0,PRXYERR_F_PROXY_CONSTRUCT_NAME ,0),"proxy_construct_name"},
    {ERR_PACK(0,PRXYERR_F_VOMS_GET_CERT_TYPE,0),"voms_get_cert_type"},
    {0,NULL},
};

static ERR_STRING_DATA prxyerr_str_reasons[]=
{
    {PRXYERR_R_PROCESS_PROXY_KEY, "processing proxy key"},
    {PRXYERR_R_PROCESS_REQ, "creating proxy req"},
    {PRXYERR_R_PROCESS_SIGN, "while signing proxy req"},
    {PRXYERR_R_MALFORM_REQ, "malformed proxy req"},
    {PRXYERR_R_SIG_VERIFY, "proxy req signature verification error"},
    {PRXYERR_R_SIG_BAD, "proxy req signature does not match"},
    {PRXYERR_R_PROCESS_PROXY, "processing user proxy cert"},
    {PRXYERR_R_PROXY_NAME_BAD, "proxy name does not match"},
    {PRXYERR_R_PROCESS_SIGNC, "while signing proxy cert"},
    {PRXYERR_R_BAD_PROXY_ISSUER, "invalid proxy issuer certificate"},
    {PRXYERR_R_SIGN_NOT_CA ,"user cert not signed by CA"},
    {PRXYERR_R_PROBLEM_PROXY_FILE ,"problems creating proxy file"},
    {PRXYERR_R_PROCESS_KEY, "processing key"},
    {PRXYERR_R_PROCESS_CERT, "processing cert"},
    {PRXYERR_R_PROCESS_CERTS, "unable to access trusted certificates in:"},
    {PRXYERR_R_PROCESS_PROXY, "processing user proxy cert"},
    {PRXYERR_R_NO_TRUSTED_CERTS, "check X509_CERT_DIR and X509_CERT_FILE"},
    {PRXYERR_R_PROBLEM_KEY_FILE, "bad file system permissions on private key\n"
                                 "    key must only be readable by the user"},
    {PRXYERR_R_SERVER_ZERO_LENGTH_KEY_FILE, "system key file is empty"},
    {PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE, "user private key file is empty"},
    {PRXYERR_R_PROBLEM_SERVER_NOKEY_FILE, "system key cannot be accessed"},
    {PRXYERR_R_PROBLEM_USER_NOKEY_FILE, "user private key cannot be accessed"},
    {PRXYERR_R_PROBLEM_SERVER_NOCERT_FILE, "system certificate not found"},
    {PRXYERR_R_PROBLEM_USER_NOCERT_FILE, "user certificate not found"},
    {PRXYERR_R_INVALID_CERT, "no certificate in file"},
    {PRXYERR_R_REMOTE_CRED_EXPIRED, "peer certificate has expired"},
    {PRXYERR_R_USER_CERT_EXPIRED, "user certificate has expired"},
    {PRXYERR_R_SERVER_CERT_EXPIRED, "system certificate has expired"},
    {PRXYERR_R_PROXY_EXPIRED, "proxy expired: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_NO_PROXY, "no proxy credentials: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_CRL_SIGNATURE_FAILURE, "invalid signature on a CRL"},
    {PRXYERR_R_CRL_NEXT_UPDATE_FIELD, "invalid nextupdate field in CRL"},
    {PRXYERR_R_CRL_HAS_EXPIRED, "outdated CRL found, revoking all certs till you get new CRL"},
    {PRXYERR_R_CERT_REVOKED, "certificate revoked by CRL"},
    {PRXYERR_R_NO_HOME, "can't determine HOME directory"},
    {PRXYERR_R_KEY_CERT_MISMATCH, "user key and certificate don't match"},
    {PRXYERR_R_WRONG_PASSPHRASE, "wrong pass phrase"},
    {PRXYERR_R_CA_POLICY_VIOLATION, "remote certificate CA signature not allowed by policy"},
    {PRXYERR_R_CA_POLICY_ERR,"no matching CA found in file for remote certificate"},
    {PRXYERR_R_CA_NOFILE,"could not find CA policy file"},
    {PRXYERR_R_CA_NOPATH,"could not determine path to CA policy file"},
    {PRXYERR_R_CA_POLICY_RETRIEVE, "CA policy retrieve problems"},
    {PRXYERR_R_CA_POLICY_PARSE, "CA policy parse problems"},
    {PRXYERR_R_CA_UNKNOWN,"remote certificate signed by unknown CA"},
    {PRXYERR_R_PROBLEM_CLIENT_CA, "problems getting client_CA list"},
    {PRXYERR_R_CB_NO_PW, "no proxy credentials: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_CB_CALLED_WITH_ERROR,"certificate validation error"},
    {PRXYERR_R_CB_ERROR_MSG, "certificate validation error"},
    {PRXYERR_R_CLASS_ADD_OID,"can't find CLASS_ADD OID"},
    {PRXYERR_R_CLASS_ADD_EXT,"problem adding CLASS_ADD Extension"},
    {PRXYERR_R_DELEGATE_VERIFY,"problem verifiying the delegate extension"},
    {PRXYERR_R_EXT_ADD,"problem adding extension"},
    {PRXYERR_R_DELEGATE_CREATE,"problem creating delegate extension"},
    {PRXYERR_R_DELEGATE_COPY,"problem copying delegate extension to proxy"},
    {PRXYERR_R_BUFFER_TOO_SMALL,"buffer too small"},
    {PRXYERR_R_CERT_NOT_YET_VALID,"remote certificate not yet valid"},
    {PRXYERR_R_LOCAL_CA_UNKNOWN,"cannot find a locally trusted CA certificate that matches the issuer of the peer credential"},
    {PRXYERR_R_OUT_OF_MEMORY,"out of memory error"},
    {PRXYERR_R_BAD_ARGUMENT,"bad argument"},
    {PRXYERR_R_BAD_MAGIC,"bad magic number"},
    {PRXYERR_R_UNKNOWN_CRIT_EXT,"unable to handle critical extension"},
    {PRXYERR_R_NON_COMPLIANT_PROXY,"non compliant proxy"},
    {PRXYERR_R_ERROR_GETTING_NAME_ENTRY_OF_SUBJECT, "error getting name entry from certificate subject name"},
    {PRXYERR_R_ERROR_COPYING_SUBJECT, "error copying subject"},
    {PRXYERR_R_ERROR_GETTING_CN_ENTRY, "error getting CommonName entry from certificate subject name"},
    {PRXYERR_R_ERROR_BUILDING_SUBJECT, "error building certificate subject for proxy name integrity checks"},
    {0,NULL}
};

int my_txt2nid(char *name)
{
  ASN1_OBJECT *obj = OBJ_txt2obj(name,1);
  int nid = OBJ_obj2nid(obj);
  ASN1_OBJECT_free(obj);

  return nid;
}

/*********************************************************************
Function: X509_NAME_cmp_no_set

Description:
        To circumvent a bug with adding X509_NAME_ENTRIES
        with the wrong "set", we will compare names without
        the set.
        This is a temporary fix which will be removed when we
        fix the creation of the names using the correct sets.
        This is only being done this way for some compatability
        while installing the these fixes.
        This fix is needed in all previous versions of Globus.

Parameters:
        same as X509_NAME_cmp
Returns :
        same as X509_NAME_cmp
********************************************************************/
static int
X509_NAME_cmp_no_set(
    X509_NAME *                         a,
    X509_NAME *                         b)
{
    int                                 i;
    int                                 j;
    X509_NAME_ENTRY *                   na;
    X509_NAME_ENTRY *                   nb;

    if (X509_NAME_entry_count(a) != X509_NAME_entry_count(b))
    {
        return(X509_NAME_entry_count(a) - X509_NAME_entry_count(b));
    }

    for (i=X509_NAME_entry_count(a)-1; i>=0; i--)
    {
        na = X509_NAME_get_entry(a,i);
        nb = X509_NAME_get_entry(b,i);
        ASN1_STRING* sa = X509_NAME_ENTRY_get_data(na);
        ASN1_STRING* sb = X509_NAME_ENTRY_get_data(nb);
        j = ASN1_STRING_length(sa) - ASN1_STRING_length(sb);

        if (j)
        {
            return(j);
        }

        j = memcmp(ASN1_STRING_get0_data(sa),
                   ASN1_STRING_get0_data(sb),
                   ASN1_STRING_length(sa));
        if (j)
        {
            return(j);
        }
    }

    /* We will check the object types after checking the values
     * since the values will more often be different than the object
     * types. */
    for (i=X509_NAME_entry_count(a)-1; i>=0; i--)
    {
        na = X509_NAME_get_entry(a,i);
        nb = X509_NAME_get_entry(b,i);
        j = OBJ_cmp(X509_NAME_ENTRY_get_object(na),X509_NAME_ENTRY_get_object(nb));

        if (j)
        {
            return(j);
        }
    }
    return(0);
}

#ifdef WIN32
/*********************************************************************
Function: getuid, getpid

Descriptions:
        For Windows95, WIN32, we don't have these, so we will default
    to using uid 0 and pid 0 Need to look at this better for NT.
******************************************************************/
static unsigned long
getuid()
{
    return 0;
}

static int
getpid()
{
    return 0;
}

#endif /* WIN32 */


#if SSLEAY_VERSION_NUMBER < 0x0900

/**********************************************************************
Function: ERR_add_error_data()

Description:
    Dummy routine only defined if running with SSLeay-0.8.x
    this feature was introduced with SSLeay-0.9.0

Parameters:

Returns:
**********************************************************************/
void PRIVATE
ERR_add_error_data( VAR_PLIST( int, num ))
    VAR_ALIST
{
    VAR_BDEFN(args, int, num);
}

/**********************************************************************
Function: ERR_get_error_line_data()

Description:
    Dummy routine only defined if running with SSLeay-0.8.x
    this feature was introduced with SSLeay-0.9.0. We will
    simulate it for 0.8.1

Parameters:

Returns:
**********************************************************************/
unsigned long PRIVATE
ERR_get_error_line_data(
    char **                             file,
    int *                               line,
    char **                             data,
    int *                               flags)
{
    if (data)
    {
        *data = "";
    }

    if (flags)
    {
        *flags = 0;
    }

    return (ERR_get_error_line(file, line));
}

#endif

/**********************************************************************
Function: ERR_set_continue_needed()

Description:
        Sets state information which error display routines can use to
        determine if the error just added is enough information to describe
        the error or if further error information need displayed.
        (By default gss_display_status will only show one user level error)

        note: This function must be called after (or instead of) the ssl add error
        data functions.

Parameters:

Returns:
**********************************************************************/

void PRIVATE
ERR_set_continue_needed(void)
{
    ERR_STATE *es;
    es = ERR_get_state();
    es->err_data_flags[es->top] =
        es->err_data_flags[es->top] | ERR_DISPLAY_CONTINUE_NEEDED;
}


int
ERR_load_proxy_error_strings(){

  static int do_init = 1;

  if (do_init) {

    do_init = 0;

    ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,prxyerr_str_functs);
    ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,prxyerr_str_reasons);
  }

  return 0;
}

/**********************************************************************
Function: ERR_load_prxyerr_strings()

Description:
    Sets up the error tables used by SSL and adds ours
    using the ERR_LIB_USER
    Only the first call does anything.
        Will also add any builtin objects for SSLeay.

Parameters:
    i should be zero the first time one of the ERR_load functions
    is called and non-zero for each additional call.

Returns:
**********************************************************************/

int PRIVATE
ERR_load_prxyerr_strings(
    int                                 i)
{
    static int                          init = 1;
    struct stat                         stx;
    clock_t cputime;
#if SSLEAY_VERSION_NUMBER  >= 0x00904100L
    const char *                        randfile;
#else
    char *                              randfile;
#endif
#if SSLEAY_VERSION_NUMBER >=  0x0090581fL && !defined(OPENSSL_NO_EGD)
    char *                              egd_path;
#endif
    char                                buffer[200];

    if (init)
    {
        init = 0;

#ifndef RAND_DO_NOT_USE_CLOCK
        clock();
#endif
        if (i == 0)
        {
            SSL_load_error_strings();
        }

        if (OBJ_txt2nid("1.3.6.1.4.1.3536.1.1.1.1") == NID_undef) {
          int nid = OBJ_create("1.3.6.1.4.1.3536.1.1.1.1","CLASSADD","ClassAdd");
          assert(nid != NID_undef && "OBJ_create failed");
        }

        if (OBJ_txt2nid("1.3.6.1.4.1.3536.1.1.1.2") == NID_undef) {
          int nid = OBJ_create("1.3.6.1.4.1.3536.1.1.1.2","DELEGATE","Delegate");
          assert(nid != NID_undef && "OBJ_create failed");
        }

        if (OBJ_txt2nid("1.3.6.1.4.1.3536.1.1.1.3") == NID_undef) {
          int nid = OBJ_create("1.3.6.1.4.1.3536.1.1.1.3","RESTRICTEDRIGHTS",
                               "RestrictedRights");
          assert(nid != NID_undef && "OBJ_create failed");
        }

        if (OBJ_txt2nid("0.9.2342.19200300.100.1.1") == NID_undef) {
          int nid = OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");
          assert(nid != NID_undef && "OBJ_create failed");
        }

        ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,prxyerr_str_functs);
        ERR_load_strings(ERR_USER_LIB_PRXYERR_NUMBER,prxyerr_str_reasons);

        /*
         * We need to get a lot of randomness for good security
         * OpenSSL will use /dev/urandom (if available),
         * uid, time, and gid.
         *
         * If user has RANDFILE set, or $HOME/.rnd
         * load it for extra random seed.
         * This may also not be enough, so we will also add in
         * the time it takes to run this routine, which includes
         * reading the randfile.
         * Later we will also add in some keys and some stats
         * if we have them.
         * look for RAND_add in this source file.
         *
         * Other methods we could use:
         *  * Librand from  Don Mitchell and Matt Blaze
         *  * Doing a netstat -in
         *  * some form of pstat
         * But /dev/random and/or egd should be enough.
         */

        randfile = RAND_file_name(buffer,200);

        if (randfile && access(randfile, R_OK) == 0)
        {
            RAND_load_file(randfile,1024L*1024L);
        }

#if SSLEAY_VERSION_NUMBER >=  0x0090581fL && !defined(OPENSSL_NO_EGD)
        /*
         * Try to use the Entropy Garthering Deamon
         * See the OpenSSL crypto/rand/rand_egd.c
         */
        egd_path = getenv("EGD_PATH");
        if (egd_path == NULL)
        {
            egd_path = "/etc/entropy";
        }
        RAND_egd(egd_path);
#endif

        /* if still not enough entropy*/
        if (RAND_status() == 0)
        {
            stat("/tmp",&stx); /* get times /tmp was modified */
            RAND_add((void*)&stx,sizeof(stx),16);
        }

#ifndef RAND_DO_NOT_USE_CLOCK
        cputime = clock();
        RAND_add((void*)&cputime, sizeof(cputime),8);
#endif

        i++;
#ifdef USE_PKCS11
        i = ERR_load_scerr_strings(i);
#endif

    }
    return i;
}

/**********************************************************************
Function:       checkstat()
Description:    check the status of a file
Parameters:
Returns:
                0 pass all the following tests
                1 does not exist
                2 not owned by user
                3 readable by someone else
                4 zero length
**********************************************************************/
static int checkstat(const char* filename)
{
    struct stat                         stx;

    if (stat(filename,&stx) != 0)
    {
        return 1;
    }

    /*
     * use any stat output as random data, as it will
     * have file sizes, and last use times in it.
     */
    RAND_add((void*)&stx,sizeof(stx),2);

#if !defined(WIN32) && !defined(TARGET_ARCH_CYGWIN)
    if (stx.st_uid != getuid())
    {
      return 2;
    }

    if (stx.st_mode & 066)
    {
        return 3;
    }

#endif /* !WIN32 && !TARGET_ARCH_CYGWIN */

    if (stx.st_size == 0)
    {
        return 4;
    }
    return 0;

}

/**********************************************************************
Function: proxy_load_user_proxy()

Description:
        Given the user_proxy file, skip the first cert,
        and add any additional certs to the cert_chain.
        These must be additional proxies, or the user's cert
        which signed the proxy.
        This is based on the X509_load_cert_file routine.

Parameters:

Returns:
**********************************************************************/

int PRIVATE
proxy_load_user_proxy(
    STACK_OF(X509) *                    cert_chain,
    const char *                        file)
{

    int                                 ret = -1;
    BIO *                               in = NULL;
    int                                 count=0;
    X509 *                              x = NULL;

    if (file == NULL)
      return(1);

    in = BIO_new(BIO_s_file());


    if ((in == NULL) || (BIO_read_filename(in,file) <= 0))
    {
        X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    for (;;)
    {
        x = PEM_read_bio_X509(in,NULL, OPENSSL_PEM_CB(NULL,NULL));
        if (x == NULL)
        {
            if ((ERR_GET_REASON(ERR_peek_last_error()) ==
                 PEM_R_NO_START_LINE) && (count > 0))
            {
                ERR_clear_error();
                break;
            }
            else
            {
                X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
                goto err;
            }
        }

        if (count) {
          (void)sk_X509_push(cert_chain,x);
        } else {
          X509_free(x);
        }

        count++;

    }
    ret = count;

err:
    X509_free(x);
    BIO_free(in);

    return(ret);
}


/**********************************************************************
Function: proxy_genreq()

Description:
        generate certificate request for a proxy certificate.
        This is based on using the current user certificate.
        If the current user cert is NULL, we are asking fke the server
    to fill this in, and give us a new cert. Used with k5cert.

Parameters:

Returns:
**********************************************************************/

int PRIVATE
proxy_genreq(
    X509 *                              ucert,
    X509_REQ **                         reqp,
    EVP_PKEY **                         pkeyp,
    int                                 bits,
    const char *                        newdn,
    void                                (*callback)(int, int, void*))

{
    RSA *                               rsa = NULL;
    EVP_PKEY *                          pkey = NULL;
    EVP_PKEY *                          upkey = NULL;
    X509_NAME *                         name = NULL;
    X509_REQ *                          req = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    int                                 rbits;
    BIGNUM *                            rsa_exp = NULL;
    BN_GENCB *                          cb = NULL;

    if (bits)
    {
        rbits = bits;
    }
    else if (ucert)
    {
        if ((upkey = X509_get_pubkey(ucert)) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
            goto err;
        }

        if (!EVP_PKEY_get0_RSA(upkey))
        {
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
            goto err;
        }

        rbits = 8 * EVP_PKEY_size(upkey);
        EVP_PKEY_free(upkey);
    }
    else
    {
        rbits = 512;
    }

    if ((pkey = EVP_PKEY_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }

    if ((rsa_exp = BN_new()) == NULL || ! BN_set_word(rsa_exp, RSA_F4))
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }

    if ((cb = BN_GENCB_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }
    BN_GENCB_set_old(cb, callback, NULL);

    if ((rsa = RSA_new()) == NULL) {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }

    if (RSA_generate_key_ex(rsa, rbits, rsa_exp, cb))
    {
      BN_free(rsa_exp);
      rsa_exp = NULL;
      BN_GENCB_free(cb);
      cb = NULL;
    }
    else
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }

    if (EVP_PKEY_assign_RSA(pkey,rsa))
    {
      rsa = NULL;
    }
    else
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }

    if ((req = X509_REQ_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
    }

    X509_REQ_set_version(req,0L);

    if (!newdn) {
      if (ucert) {

        if ((name = X509_NAME_dup(X509_get_subject_name(ucert))) == NULL) {
          PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
          goto err;
        }
      }
      else {
        name = X509_NAME_new();
      }


      if ((ne = X509_NAME_ENTRY_create_by_NID(NULL,NID_commonName,
                                              V_ASN1_APP_CHOOSE,
                                              (unsigned char *)"proxy",
                                              -1)) == NULL) {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
      }
      X509_NAME_add_entry(name,
                          ne,
                          X509_NAME_entry_count(name),
                          fix_add_entry_asn1_set_param);
    }
    else {
      name = make_DN(newdn);
      if (!name) {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_REQ);
        goto err;
      }
    }

    X509_REQ_set_subject_name(req,name);
    X509_NAME_free(name);
    name = NULL;
    X509_REQ_set_pubkey(req,pkey);

    EVP_MD const* md = EVP_get_digestbynid(X509_REQ_get_signature_nid(req));

    if ( ucert ){

      md = EVP_get_digestbynid(X509_get_signature_nid(ucert));

    }

    if (md == NULL) md = EVP_sha1();

    if (!X509_REQ_sign(req,pkey,md))
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_SIGN);
        goto err;
    }

    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
        ne = NULL;
    }

    *pkeyp = pkey;
    *reqp = req;
    return 0;

err:
    if (upkey)
      EVP_PKEY_free(upkey);

    if (rsa_exp)
    {
      BN_free(rsa_exp);
    }
    if (cb)
    {
      BN_GENCB_free(cb);
    }
    if(rsa)
    {
        RSA_free(rsa);
    }
    if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
    if (name)
    {
        X509_NAME_free(name);
    }
    if (req)
    {
        X509_REQ_free(req);
    }
    if (ne)
    {
        X509_NAME_ENTRY_free(ne);
    }
    return 1;
}


/**
 * Sign a certificate request
 *
 * This function is a wrapper function for proxy_sign_ext. The subject
 * name of the resulting certificate is generated by adding either
 * cn=proxy or cn=limited proxy to the subject name of user_cert. The
 * issuer name is set to the subject name of user_cert.
 *
 * @param user_cert
 *        A certificate to be used for subject and issuer name
 *        information if that information isn't provided.
 * @param user_private_key
 *        The private key to be used for signing the certificate
 *        request.
 * @param req
 *        The certificate request
 * @param new_cert
 *        This parameter will contain the signed certficate upon
 *        success.
 * @param seconds
 *        The number of seconds the new cert is going to be
 *        valid. The validity should not exceed that of the issuing
 *        key pair. If this parameter is 0 the generated cert will
 *        have the same lifetime as the issuing key pair.
 * @param extensions
 *        Extensions to be placed in the new certificate.
 * @param limited_proxy
 *        If this value is non zero the resulting cert will be a
 *        limited proxy.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int PRIVATE
proxy_sign(
    X509 *                              user_cert,
    EVP_PKEY *                          user_private_key,
    X509_REQ *                          req,
    X509 **                             new_cert,
    int                                 seconds,
    STACK_OF(X509_EXTENSION) *          extensions,
    int                                 limited_proxy,
    int                                 proxyver,
    const char *                        newdn,
    const char *                        newissuer,
    int                                 pastproxy,
    const char *                        newserial,
    int                                 selfsigned
)
{
    char *                              newcn;
    X509_NAME *                         subject_name = NULL;
    X509_NAME *                         issuer_name = NULL;
    int                                 rc = 0;

    unsigned char                       md[SHA_DIGEST_LENGTH];
    unsigned int                        len;
    EVP_MD const*                       sig_algo;

    sig_algo = EVP_get_digestbynid(X509_REQ_get_signature_nid(req));
    if (sig_algo == NULL) sig_algo = EVP_sha1();

    if(proxyver>=3) {
      unsigned sub_hash;
      EVP_MD const* cn_sig_algo;
      EVP_PKEY* req_public_key;

      cn_sig_algo = EVP_sha1();
      req_public_key = X509_REQ_get_pubkey(req);

#ifdef TYPEDEF_I2D_OF
      ASN1_digest((i2d_of_void*)i2d_PUBKEY, cn_sig_algo, (char *) req_public_key, md, &len);
#else
      ASN1_digest(i2d_PUBKEY, cn_sig_algo, (char *) req_public_key, md, &len);
#endif
      EVP_PKEY_free(req_public_key);

      sub_hash = md[0] | md[1] << 8 | md[2] << 16 | md[3] << 24;

      newcn = snprintf_wrap("%u", sub_hash);
      newserial = snprintf_wrap("%x", sub_hash);
    }
    else {
      if(limited_proxy)
        newcn = "limited proxy";
      else
        newcn = "proxy";
    }

    if (newdn == NULL) {
      if(proxy_construct_name(
                              user_cert,
                              &subject_name,
                              newcn, -1)) {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_PROCESS_SIGN);
        if (proxyver >= 3) {
          free(newcn);
	  free((void*)newserial);
	}
        return 1;
      }
    }
    else
      subject_name = make_DN(newdn);

    if (newissuer)
      issuer_name = make_DN(newissuer);
    else
      issuer_name = NULL;

    if(proxy_sign_ext(user_cert,
                      user_private_key,
                      sig_algo,
                      req,
                      new_cert,
                      subject_name,
                      issuer_name,
                      seconds,
                      extensions,
                      proxyver,
                      pastproxy,
                      newserial,
                      selfsigned))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_PROCESS_SIGN);
        rc = 1;
    }

    X509_NAME_free(subject_name);

    if (issuer_name)
      X509_NAME_free(issuer_name);

    if (proxyver >= 3) {
      free(newcn);
      free((void*)newserial);
    }

    return rc;
}

/**
 * Sign a certificate request
 *
 * This function signs the given certificate request. Before signing
 * the certificate the certificate's subject and issuer names may be
 * replaced and extensions may be added to the certificate.
 *
 * @param user_cert
 *        A certificate to be used for lifetime and serial number
 *        information if that information isn't provided.
 * @param user_private_key
 *        The private key to be used for signing the certificate
 *        request.
 * @param method
 *        The method to employ for signing
 * @param req
 *        The certificate request
 * @param new_cert
 *        This parameter will contain the signed certficate upon
 *        success.
 * @param subject_name
 *        The subject name to be used for the new certificate. If no
 *        subject name is provided the subject name in the certificate
 *        request will remain untouched.
 * @param issuer_name
 *        The issuer name to be used for the new certificate. If no
 *        issuer name is provided the issuer name will be set to the
 *        subject name of the user cert.
 * @param seconds
 *        The number of seconds the new cert is going to be
 *        valid. The validity should not exceed that of the issuing
 *        key pair. If this parameter is 0 the generated cert will
 *        have the same lifetime as the issuing key pair.
 * @param serial_num
 *        The serial number to be used for the new cert. If this
 *        parameter is 0 the serial number of the user_cert is used.
 * @param extensions
 *        Extensions to be placed in the new certificate.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int PRIVATE
proxy_sign_ext(
    X509 *                    user_cert,
    EVP_PKEY *                user_private_key,
    const EVP_MD *            method,
    X509_REQ *                req,
    X509 **                   new_cert,
    X509_NAME *               subject_name,
    X509_NAME *               issuer_name,
    int                       seconds,
    STACK_OF(X509_EXTENSION) *extensions,
    int                       proxyver,
    int                       pastproxy,
    const char               *newserial,
    int                       selfsigned)
{
    EVP_PKEY *                          new_public_key = NULL;
    EVP_PKEY *                          tmp_public_key = NULL;
    time_t                              time_diff, time_now, time_after;
    ASN1_UTCTIME *                      asn1_time = NULL;
    int                                 i;
    unsigned int                        len;
    EVP_MD const*                       sig_algo;

    sig_algo = EVP_sha1();

    *new_cert = NULL;

    if ((new_public_key=X509_REQ_get_pubkey(req)) == NULL) {
      PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_MALFORM_REQ);
      goto err;
    }

    i = X509_REQ_verify(req,new_public_key);
    EVP_PKEY_free(new_public_key);
    new_public_key = NULL;

    if (i < 0)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_SIG_VERIFY);
        goto err;
    }

    if (i == 0)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_SIG_BAD);
        goto err;
    }

    /* signature ok. */

    if ((*new_cert = X509_new()) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    /* set the subject name */

    if(subject_name && !X509_set_subject_name(*new_cert,subject_name))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    /* DEE? will use same serial number, this may help
     * with revocations, or may cause problems.
     */

    if (newserial) {
      BIGNUM *bn = NULL;
      if (BN_hex2bn(&bn, newserial) != 0) {
        ASN1_INTEGER *a_int = BN_to_ASN1_INTEGER(bn, NULL);
        BN_free(bn);
        /* Note:  The a_int == NULL case is handled below. */
        X509_set_serialNumber(*new_cert, a_int);
        ASN1_INTEGER_free(a_int);
      }
    }
    else if (proxyver > 2) {
      unsigned char md[SHA_DIGEST_LENGTH + 1];

      ASN1_INTEGER_free(X509_get_serialNumber(*new_cert));

      new_public_key = X509_REQ_get_pubkey(req);
#ifdef TYPEDEF_I2D_OF
      ASN1_digest((i2d_of_void*)i2d_PUBKEY, sig_algo, (char *) new_public_key, md, &len);
#else
      ASN1_digest(i2d_PUBKEY, sig_algo, (char *) new_public_key, md, &len);
#endif
      md[len] = '\0';

      EVP_PKEY_free(new_public_key);
      new_public_key = NULL;

      BIGNUM* bn = NULL;
      if (BN_hex2bn(&bn, (char*)md) != 0) {
        ASN1_INTEGER *a_int = BN_to_ASN1_INTEGER(bn, NULL);
        BN_free(bn);
        X509_set_serialNumber(*new_cert, a_int);
        ASN1_INTEGER_free(a_int);
      }

    }
    else if (selfsigned) {
      ASN1_INTEGER *a_int = ASN1_INTEGER_new();
      if (a_int) {
        ASN1_INTEGER_set(a_int, 1);
        X509_set_serialNumber(*new_cert, a_int);
        ASN1_INTEGER_free(a_int);
      }
      else
        goto err;
    }
    else {
      ASN1_INTEGER *a_int = ASN1_INTEGER_dup(X509_get0_serialNumber(user_cert));
      X509_set_serialNumber(*new_cert, a_int);
      ASN1_INTEGER_free(a_int);
    }

    /* set the issuer name */

    if (issuer_name)
    {
        if(!X509_set_issuer_name(*new_cert,issuer_name))
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
    }
    else
    {
        if(!X509_set_issuer_name(*new_cert,X509_get_subject_name(user_cert)))
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
    }

    /* Allow for a five minute clock skew here. */

    X509_gmtime_adj(X509_get_notBefore(*new_cert),-5*60 -pastproxy);

    /* DEE? should accept an seconds parameter, and set to min of
     * hours or the ucert notAfter
     * for now use seconds if not zero.
     */

    if (selfsigned) {
      X509_gmtime_adj(X509_get_notAfter(*new_cert),(long) seconds - pastproxy);
    }
    else {
      /* doesn't create a proxy longer than the user cert */
      asn1_time = ASN1_UTCTIME_new();
      X509_gmtime_adj(asn1_time, -pastproxy);
      time_now = ASN1_UTCTIME_mktime(asn1_time);
      ASN1_UTCTIME_free(asn1_time);
      time_after = ASN1_UTCTIME_mktime(X509_get_notAfter(user_cert));
      time_diff = time_after - time_now;

      if(time_diff > (seconds - pastproxy)) {
        X509_gmtime_adj(X509_get_notAfter(*new_cert),(long) seconds - pastproxy);
      }
      else {
        int ret = X509_set1_notAfter(*new_cert, X509_get0_notAfter(user_cert));
        assert(ret == 1 && "X509_set1_notAfter failed");
      }
    }

    /* transfer the public key from req to new cert */
    {
      EVP_PKEY* const pub_key = X509_REQ_get_pubkey(req);
      assert(pub_key && "X509_REQ_get0_pubkey failed");
      int const ret = X509_set_pubkey(*new_cert, pub_key);
      assert(ret == 1 && "X509_set_pubkey failed");
      EVP_PKEY_free(pub_key);
    }

    /*
     * We can now add additional extentions here
     * such as to control the usage of the cert
     */

    {
      int const ret = X509_set_version(*new_cert, 2L);
      assert(ret == 1 && "X509_set_version failed");
    }

    /* Add extensions provided by the client */
    /* TODO: who frees extensions? */

    if (extensions)
    {
        for (i=0; i<sk_X509_EXTENSION_num(extensions); i++)
        {
          X509_EXTENSION* extension = sk_X509_EXTENSION_value(extensions, i);
          if (extension == NULL)
          {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
            goto err;
          }

          int const ret = X509_add_ext(*new_cert, extension, -1);

          if (ret == 0)
          {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
            goto err;
          }
        }
    }

    /* new cert is built, now sign it */

#ifndef NO_DSA
    /* DEE? not sure what this is doing, I think
     * it is adding from the key to be used to sign to the
     * new certificate any info DSA may need
     */

    tmp_public_key = X509_get_pubkey(*new_cert);

    if (EVP_PKEY_missing_parameters(tmp_public_key) &&
        !EVP_PKEY_missing_parameters(user_private_key))
    {
        EVP_PKEY_copy_parameters(tmp_public_key,user_private_key);
    }
#endif

    EVP_PKEY_free(tmp_public_key);

    if (!X509_sign(*new_cert,user_private_key,method))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_SIGNC);
        goto err;
    }

    return 0;

err:
    /* free new_cert upon error */

    if (*new_cert)
    {
        X509_free(*new_cert);
    }

    if (new_public_key)
      EVP_PKEY_free(new_public_key);

    return 1;
}




/**
 * Construct a X509 name
 *
 * This function constructs a X509 name by taking the subject name of
 * the certificate and adding a new CommonName field with value newcn
 * (if this parameter is non NULL). The resulting name should be freed
 * using X509_NAME_free.
 *
 * @param cert
 *        The certificate to extract the subject name from.
 * @param name
 *        The resulting name
 * @param newcn
 *        The value of the CommonName field to add. If this value is
 *        NULL this function just returns a copy of the subject name
 *        of the certificate.
 *
 * @return
 *        This functions returns 0 upon success, 1 upon failure. It
 *        will also place a more detailed error on an error stack.
 */

int PRIVATE
proxy_construct_name(
    X509 *                              cert,
    X509_NAME **                        name,
    char *                              newcn,
    unsigned int                        len)
{
    X509_NAME_ENTRY *                   name_entry = NULL;
    *name = NULL;

    if ((*name = X509_NAME_dup(X509_get_subject_name(cert))) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    if(newcn)
    {
        if ((name_entry = X509_NAME_ENTRY_create_by_NID(NULL,
							NID_commonName,
                                                        V_ASN1_APP_CHOOSE,
                                                        (unsigned char *)newcn,
                                                        len)) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }

        if (!X509_NAME_add_entry(*name,
                                 name_entry,
                                 X509_NAME_entry_count(*name),
                                 fix_add_entry_asn1_set_param))
        {
            PRXYerr(PRXYERR_F_PROXY_CONSTRUCT_NAME,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
        X509_NAME_ENTRY_free(name_entry);
    }

    return 0;

err:
    if (*name)
    {
        X509_NAME_free(*name);
    }

    if (name_entry)
    {
        X509_NAME_ENTRY_free(name_entry);
    }

    return 1;

}



/**********************************************************************
Function: proxy_marshal_bp()

Description:
        Write to a bio the proxy certificate, key, users certificate,
        and any other certificates need to use the proxy.

Parameters:

Returns:
**********************************************************************/
int PRIVATE
proxy_marshal_bp(
    BIO *                               bp,
    X509 *                              ncert,
    EVP_PKEY *                          npkey,
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain)
{
    X509 *                              cert;

    if (!PEM_write_bio_X509(bp,ncert))
    {
        return 1;
    }

    if (!PEM_write_bio_RSAPrivateKey(bp,
                                     EVP_PKEY_get0_RSA(npkey),
                                     NULL,
                                     NULL,
                                     0,
                                     OPENSSL_PEM_CB(NULL,NULL)))
    {
        return 2;
    }

    if (ucert)
    {
        if (!PEM_write_bio_X509(bp,ucert))
        {
            return 3;
        }
    }

    if (cert_chain)
    {
        /*
         * add additional certs, but not our cert, or the
         * proxy cert, or any self signed certs
         */
        int i;

        for(i=0; i < sk_X509_num(cert_chain); i++)
        {
            cert = sk_X509_value(cert_chain,i);
            if (!(!X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                        X509_get_subject_name(ncert))
                  || (ucert &&
                      !X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                            X509_get_subject_name(ucert)))
                  || !X509_NAME_cmp_no_set(X509_get_subject_name(cert),
                                           X509_get_issuer_name(cert))))
            {
                if (!PEM_write_bio_X509(bp,cert))
                {
                    return 4;
                }
            }
        }
    }

    return 0;
}

/**********************************************************************
Function: proxy_verify_init()

Description:

Parameters:

Returns:
**********************************************************************/

void
proxy_verify_init(
    proxy_verify_desc *                 pvd,
    proxy_verify_ctx_desc *             pvxd)
{

    pvd->magicnum = PVD_MAGIC_NUMBER; /* used for debuging */
    pvd->flags = 0;
    pvd->previous = NULL;
    pvd->pvxd = pvxd;
    pvd->proxy_depth = 0;
    pvd->cert_depth = 0;
    pvd->cert_chain = NULL;
    pvd->limited_proxy = 0;
    pvd->multiple_limited_proxy_ok = 0;
    pvd->cert_store = NULL;
    pvd->recursive_depth = 0;
}

/**********************************************************************
Function: proxy_verify_ctx_init()

Description:

Parameters:

Returns:
**********************************************************************/

void
proxy_verify_ctx_init(
    proxy_verify_ctx_desc *             pvxd)
{

    pvxd->magicnum = PVXD_MAGIC_NUMBER; /* used for debuging */
    pvxd->certdir = NULL;
    pvxd->goodtill = 0;

}
/**********************************************************************
Function: proxy_verify_release()

Description:

Parameters:

Returns:
**********************************************************************/

void
proxy_verify_release(
    proxy_verify_desc *                 pvd)
{
    pvd->cert_chain = NULL;
    pvd->pvxd = NULL;
}

/**********************************************************************
Function: proxy_verify_ctx_release()

Description:

Parameters:

Returns:
**********************************************************************/

void
proxy_verify_ctx_release(
    proxy_verify_ctx_desc *             pvxd)
{
    if (pvxd->certdir)
    {
        free(pvxd->certdir);
        pvxd->certdir = NULL;
    }
}
#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
/**********************************************************************
Function: proxy_app_verify_callback()

Description:
        SSL callback which lets us do the x509_verify_cert
        ourself. We use this to set the ctx->check_issued routine
        so we can override some of the tests if needed.

Parameters:

Returns:
        Same as X509_verify_cert
**********************************************************************/

int
proxy_app_verify_callback(X509_STORE_CTX *ctx, UNUSED(void *empty))
{

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx->check_issued = proxy_check_issued;
#else
    X509_STORE_set_check_issued(X509_STORE_CTX_get0_store(ctx), proxy_check_issued);
#endif

#if defined(X509_V_FLAG_ALLOW_PROXY_CERTS)
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
#endif

    return X509_verify_cert(ctx);
}
#endif

/* Ifdef out all extra code not needed for k5cert
 * This includes the OLDGAA
 */

#ifndef BUILD_FOR_K5CERT_ONLY



/**********************************************************************
Function: proxy_verify_name

Description:

Checks if the subject name is a proxy, and the issuer name
is the same as the subject name, but without the proxy
entry.

Returns:
        -1  if there was an error
         0  if not a proxy
         1  if a proxy
         2  if a limited proxy

*********************************************************************/
int proxy_verify_name(X509* cert){

  voms_cert_type_t cert_type;

  if (voms_get_cert_type(cert, &cert_type))
  {
    return -1;
  }

  if (!VOMS_IS_PROXY(cert_type))
  {
    return 0;
  }

  // If we reach this point, name checks on the proxy have
  // succeeded, and this is actually a proxy, inform OpenSSL
  // (is this still needed?)
  X509_set_proxy_flag(cert);
  X509_set_proxy_pathlen(cert, -1L);

  if (VOMS_IS_LIMITED_PROXY(cert_type))
  {
    X509_set_proxy_pathlen(cert, 0L);
    return 2;

  }

  return 1;
}


int PRIVATE
proxy_check_issued(UNUSED(X509_STORE_CTX *  ctx),
      X509 *                              x,
      X509 *                              issuer)
{
  int return_value;
  int return_code = 1;

  return_value = X509_check_issued(issuer, x);
  if (return_value != X509_V_OK)
  {
    return_code = 0;
    switch (return_value)
    {
      case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:

        if (proxy_verify_name(x) >= 1)
        {
          return_code = 1;
        }
        break;

      default:
        break;
    }
  }
  return return_code;
}

/**********************************************************************
Function: proxy_verify_callback()

Description:
        verify callback for SSL. Used to check that proxy
        certificates are only signed by the correct user,
        and used for debuging.

        Also on the server side, the s3_srvr.c code does not appear
        to save the peer cert_chain, like the client side does.
        We need these for additional proxies, so we need to
        copy the X509 to our own stack.

Parameters:
        ok  1 then we are given one last chance to check
                this certificate.
                0 then this certificate has failed, and ctx->error has the
                reason. We may want to override the failure.
        ctx the X509_STORE_CTX which has as a user arg, our
                proxy verify desc.

Returns:
        1 - Passed the tests
        0 - failed.  The x509_vfy.c will return a failed to caller.
**********************************************************************/

int
proxy_verify_callback(
    int                                 ok,
    X509_STORE_CTX *                    ctx)
{
    X509_OBJECT*                        obj = NULL;
    X509 *                              cert = NULL;
    X509 *                              prev_cert = NULL;

    X509_CRL *                          crl;
    X509_REVOKED *                      revoked;

    SSL *                               ssl = NULL;
    proxy_verify_desc *                 pvd;

    int                                 itsaproxy = 0;
    int                                 i;
    int                                 ret;
    time_t                              goodtill;
    char *                              ca_policy_file_path = NULL;
    char *                              cert_dir            = NULL;
    EVP_PKEY *key = NULL;
    int       objset = 0;

    /* fetch proxy specific information */
    if (!(pvd = (proxy_verify_desc *)
         X509_STORE_CTX_get_ex_data(ctx,
                                    PVD_STORE_EX_DATA_IDX)))
    {
        ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
        if (ssl)
          pvd = (proxy_verify_desc *)SSL_get_ex_data(ssl,
                                                     PVD_SSL_EX_DATA_IDX);
    }

    if (pvd) {
      if(pvd->magicnum != PVD_MAGIC_NUMBER) {
          PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_BAD_MAGIC);
          return(0);
      }
    }

    if (!ok)
    {
        switch (X509_STORE_CTX_get_error(ctx))
        {

        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            /*
             * Since OpenSSL does not know about proxies,
             * it will count them against the path length
             * So we will ignore the errors and do our
             * own checks later on, when we check the last
             * certificate in the chain we will check the chain.
             */
            ok = 1;
            break;

        case X509_V_ERR_INVALID_CA:
          /*
           * This may happen since proxy issuers are not recognized as CAs
           * by OpenSSL
           */
          prev_cert = sk_X509_value(X509_STORE_CTX_get_chain(ctx),
              X509_STORE_CTX_get_error_depth(ctx) -1);

          if (proxy_verify_name(prev_cert) > 0 && 
              proxy_check_issued(ctx, X509_STORE_CTX_get_current_cert(ctx), prev_cert)){
            ok = 1;
          }

          break;

        case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
          if (proxy_verify_name(X509_STORE_CTX_get0_cert(ctx)) > 0) {
            if (check_critical_extensions(X509_STORE_CTX_get0_cert(ctx), 1))
              /* Allows proxy specific extensions on proxies. */
              ok = 1;
          }
          break;

        default:
            break;
        }

        /* if already failed, skip the rest, but add error messages */
        if (!ok)
        {
            if (X509_STORE_CTX_get_error(ctx)==X509_V_ERR_CERT_NOT_YET_VALID)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CERT_NOT_YET_VALID);
                ERR_set_continue_needed();
            }
            else if (X509_STORE_CTX_get_error(ctx)==X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_LOCAL_CA_UNKNOWN);
                ERR_set_continue_needed();
            }
            else if (X509_STORE_CTX_get_error(ctx)==X509_V_ERR_CERT_HAS_EXPIRED)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_REMOTE_CRED_EXPIRED);
                ERR_set_continue_needed();
            }

            goto fail_verify;
        }

        X509_STORE_CTX_set_error(ctx,0);
        return(ok);
    }

    if (!pvd)
      return ok;

    /*
     * All of the OpenSSL tests have passed and we now get to
     * look at the certificate to verify the proxy rules,
     * and ca-signing-policy rules. We will also do a CRL check
     */

    ret = proxy_verify_name(X509_STORE_CTX_get_current_cert(ctx));
    if (ret < 0)
    {
        PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_BAD_PROXY_ISSUER);
        ERR_set_continue_needed();
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_SIGNATURE_FAILURE);
        goto fail_verify;
    } else if (ret > 0)
    {  /* Its a proxy */
        if (ret == 2)
        {

          pvd->limited_proxy = 1; /* its a limited proxy */

          if (X509_STORE_CTX_get_error_depth(ctx) && !pvd->multiple_limited_proxy_ok) {
            PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_LPROXY_MISSED_USED);
            ERR_set_continue_needed();
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_SIGNATURE_FAILURE);
            goto fail_verify;
          }
        }

        pvd->proxy_depth++;
        itsaproxy = 1;
    }

    if (!itsaproxy)
    {
        obj = X509_OBJECT_new();
        /** CRL checks **/
        int n = 0;
        if (obj != NULL
            && X509_STORE_get_by_subject(ctx,
                                         X509_LU_CRL,
                                         X509_get_subject_name(X509_STORE_CTX_get0_current_issuer(ctx)),
                                         obj))
        {
            objset = 1;
            crl =  X509_OBJECT_get0_X509_CRL(obj);
            assert(crl != NULL && "X509_OBJECT_get0_X509_CRL failed");

            /* verify the signature on this CRL */

            key = X509_get_pubkey(X509_STORE_CTX_get0_current_issuer(ctx));
            if (X509_CRL_verify(crl, key) <= 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_SIGNATURE_FAILURE);
                ERR_set_continue_needed();
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
                goto fail_verify;
            }

            /* Check date see if expired */

            i = X509_cmp_current_time(X509_CRL_get0_nextUpdate(crl));
            if (i == 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_NEXT_UPDATE_FIELD);
                ERR_set_continue_needed();
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
                goto fail_verify;
            }


            if (i < 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_HAS_EXPIRED);
                ERR_set_continue_needed();
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
                goto fail_verify;
            }

            /* check if this cert is revoked */

            n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
            for (i=0; i<n; i++)
            {
                revoked = (X509_REVOKED *)sk_X509_REVOKED_value(
                    X509_CRL_get_REVOKED(crl),i);

                if(!ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(revoked),
                                     X509_get_serialNumber(X509_STORE_CTX_get_current_cert(ctx))))
                {
                    long serial;
                    char buf[256];
                    char *s;
                    PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CERT_REVOKED);
                    serial = ASN1_INTEGER_get(X509_REVOKED_get0_serialNumber(revoked));
                    sprintf(buf,"%ld (0x%lX)",serial,serial);
                    s = X509_NAME_oneline(X509_get_subject_name(
                                              X509_STORE_CTX_get_current_cert(ctx)),NULL,0);

                    ERR_add_error_data(4,"Serial number = ",buf,
                                       " Subject=",s);

                    X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
                    ERR_set_continue_needed();
                    free(s);
                    s = NULL;
                    goto fail_verify;
                }
            }
        }

        if (X509_NAME_cmp(X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)),
                          X509_get_issuer_name(X509_STORE_CTX_get_current_cert(ctx))))
        {
            cert_dir = pvd->pvxd->certdir ? pvd->pvxd->certdir :
                getenv(X509_CERT_DIR);

            {
                char * error_string = NULL;
                struct policy **signings   = NULL;
                struct policy **namespaces = NULL;
                int result = SUCCESS_UNDECIDED;

                read_pathrestriction(X509_STORE_CTX_get0_chain(ctx), cert_dir, &namespaces, &signings);

                result = restriction_evaluate(X509_STORE_CTX_get0_chain(ctx), namespaces, signings);

                voms_free_policies(namespaces);
                voms_free_policies(signings);

                if (result != SUCCESS_PERMIT)
                {
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_POLICY_VIOLATION);

                    X509_STORE_CTX_set_error(ctx, X509_V_ERR_INVALID_PURPOSE);

                    if (error_string != NULL)
                    {
                        /*
                         * Seperate error message returned from policy check
                         * from above error message with colon
                         */

                        ERR_add_error_data(2, ": ", error_string);
                        free(error_string);
                    }
                    ERR_set_continue_needed();
                    goto fail_verify;
                }
                else
                {
                    if (error_string != NULL)
                    {
                        free(error_string);
                    }
                }
            }
        } 
    }

    /*
     * We want to determine the minimum amount of time
     * any certificate in the chain is good till
     * Will be used for lifetime calculations
     */

    goodtill = ASN1_UTCTIME_mktime(X509_get_notAfter(X509_STORE_CTX_get_current_cert(ctx)));
    if (pvd->pvxd->goodtill == 0 || goodtill < pvd->pvxd->goodtill)
    {
        pvd->pvxd->goodtill = goodtill;
    }

    /* We need to make up a cert_chain if we are the server.
     * The ssl code does not save this as I would expect.
     * This is used to create a new proxy by delegation.
     */

    pvd->cert_depth++;

    if (ca_policy_file_path != NULL)
    {
        free(ca_policy_file_path);
    }

    if (!check_critical_extensions(X509_STORE_CTX_get_current_cert(ctx), itsaproxy)) {
      PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_UNKNOWN_CRIT_EXT);
      X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
      goto fail_verify;
    }

    /*
     * We ignored any path length restrictions above because
     * OpenSSL was counting proxies against the limit.
     * If we are on the last cert in the chain, we
     * know how many are proxies, so we can do the
     * path length check now.
     * See x509_vfy.c check_chain_purpose
     * all we do is substract off the proxy_dpeth
     */

    if(X509_STORE_CTX_get_current_cert(ctx) == X509_STORE_CTX_get0_cert(ctx))
    {
        for (i=0; i < sk_X509_num(X509_STORE_CTX_get0_chain(ctx)); i++)
        {
            cert = sk_X509_value(X509_STORE_CTX_get0_chain(ctx),i);
            if (((i - pvd->proxy_depth) > 1) && (X509_get_proxy_pathlen(cert) != -1)
                && ((i - pvd->proxy_depth) > (X509_get_proxy_pathlen(cert) + 1))
                && (X509_get_extension_flags(cert) & EXFLAG_BCONS))
            {
              X509_STORE_CTX_set_current_cert(ctx, cert); /* point at failing cert */
              X509_STORE_CTX_set_error(ctx, X509_V_ERR_PATH_LENGTH_EXCEEDED);
                goto fail_verify;
            }
        }
    }

    EVP_PKEY_free(key);

    if (objset)
    {
      X509_OBJECT_free(obj);
    }

    return(ok);

fail_verify:

    if (key)
    {
      EVP_PKEY_free(key);
    }

    if (objset)
    {
      X509_OBJECT_free(obj);
    }

    if (X509_STORE_CTX_get_current_cert(ctx))
    {
        char *subject_s = NULL;
        char *issuer_s = NULL;

        subject_s = X509_NAME_oneline(
            X509_get_subject_name(X509_STORE_CTX_get_current_cert(ctx)),NULL,0);
        issuer_s = X509_NAME_oneline(
            X509_get_issuer_name(X509_STORE_CTX_get_current_cert(ctx)),NULL,0);

        int const error = X509_STORE_CTX_get_error(ctx);
        char const* const error_str = X509_verify_cert_error_string(error);

        switch (error)
        {
            case X509_V_OK:
            case X509_V_ERR_INVALID_PURPOSE:
            case X509_V_ERR_APPLICATION_VERIFICATION:
                 
              ERR_add_error_data(9,
                    ": ",
                    error_str ? error_str : "",
                    " [file=",
                    ca_policy_file_path ? ca_policy_file_path : "UNKNOWN",
                    ",subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    ",issuer =",
                    issuer_s ? issuer_s : "UNKNOWN",
                    "]");
            break;
            default:
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CB_CALLED_WITH_ERROR);

                ERR_add_error_data(7,
                    ": ",
                    error_str ? error_str : "",
                    " [subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    ",issuer=",
                    issuer_s ? issuer_s : "UNKNOWN",
                    "]");
        }

        free(subject_s);
        free(issuer_s);
    }
    if (ca_policy_file_path != NULL)
    {
        free(ca_policy_file_path);
    }

    return(0);

}

/**********************************************************************
Function: proxy_verify_cert_chain()

Description:

Parameters:

Returns:
**********************************************************************/

int PRIVATE
proxy_verify_cert_chain(
    X509 *                              ucert,
    STACK_OF(X509) *                    cert_chain,
    proxy_verify_desc *                 pvd)
{
    int                                 retval = 0;
    X509_STORE *                        cert_store = NULL;
    X509_LOOKUP *                       lookup = NULL;
    X509_STORE_CTX*                     csc = NULL;
    X509 *                              xcert = NULL;
    X509 *                              scert = NULL;
    int cscinitialized = 0;

    scert = ucert;
    cert_store = X509_STORE_new();
    X509_STORE_set_verify_cb(cert_store, proxy_verify_callback);
#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
    /* override the check_issued with our version */
    X509_STORE_set_check_issued(cert_store, proxy_check_issued);
#endif
    if (cert_chain != NULL)
    {
        int i =0;
        for (i=0;i<sk_X509_num(cert_chain);i++)
        {
            xcert = sk_X509_value(cert_chain,i);
            if (!scert)
            {
                scert = xcert;
            }
            else
            {
                int j = X509_STORE_add_cert(cert_store, xcert);
                if (!j)
                {
                    if ((ERR_GET_REASON(ERR_peek_error()) ==
                         X509_R_CERT_ALREADY_IN_HASH_TABLE))
                    {
                        ERR_clear_error();
                        break;
                    }
                    else
                    {
                        /*DEE need errprhere */
                        goto err;
                    }
                }
            }
        }
    }
    if ((lookup = X509_STORE_add_lookup(cert_store,
                                        X509_LOOKUP_hash_dir())))
    {
        X509_LOOKUP_add_dir(lookup,pvd->pvxd->certdir,X509_FILETYPE_PEM);
        csc = X509_STORE_CTX_new();
        X509_STORE_CTX_init(csc,cert_store,scert,NULL);
        cscinitialized = 1;
        X509_STORE_CTX_set_ex_data(csc,
                                   PVD_STORE_EX_DATA_IDX, (void *)pvd);
#ifdef X509_V_FLAG_ALLOW_PROXY_CERTS
        X509_STORE_CTX_set_flags(csc, X509_V_FLAG_ALLOW_PROXY_CERTS);
#endif
        if(!X509_verify_cert(csc))
        {
            goto err;
        }
    }
    retval = 1;

err:
    if (cscinitialized)
      X509_STORE_CTX_free(csc);
    if (cert_store)
      X509_STORE_free(cert_store);
    return retval;
}
#endif /* NO_PROXY_VERIFY_CALLBACK */


/**********************************************************************
Function: proxy_get_filenames()

Description:
    Gets the filenames for the various files used
    to store the cert, key, cert_dir and proxy.


    Environment variables to use:
        X509_CERT_DIR   Directory of trusted certificates
                        File names are hash values, see the SSLeay
                        c_hash script.
        X509_CERT_FILE  File of trusted certifiates
        X509_USER_PROXY File with a proxy certificate, key, and
                        additional certificates to makeup a chain
                        of certificates used to sign the proxy.
        X509_USER_CERT  User long term certificate.
        X509_USER_KEY   private key for the long term certificate.

    All of these are assumed to be in PEM form. If there is a
    X509_USER_PROXY, it will be searched first for the cert and key.
    If not defined, but a file /tmp/x509up_u<uid> is
    present, it will be used, otherwise the X509_USER_CERT
    and X509_USER_KEY will be used to find the certificate
    and key. If X509_USER_KEY is not defined, it will be assumed
    that the key is is the same file as the certificate.

    If windows, look in the registry HKEY_CURRENT_USER for the
    GSI_REGISTRY_DIR, then look for the x509_user_cert, etc.

    Then try $HOME/.globus/usercert.pem
    and $HOME/.globus/userkey.pem
        Unless it is being run as root, then look for
        /etc/grid-security/hostcert.pem and /etc/grid-security/hostkey.pem

    X509_CERT_DIR and X509_CERT_FILE can point to world readable
    shared director and file. One of these must be present.
    if not use $HOME/.globus/certificates
        or /etc/grid-security/certificates
        or $GLOBUS_DEPLOY_PATH/share/certificates
        or $GLOBUS_LOCATION/share/certificates
        or $GSI_DEPLOY_PATH/share/certificates
        or $GSI_INSTALL_PATH/share/certificates

    The file with the key must be owned by the user,
    and readable only by the user. This could be the X509_USER_PROXY,
    X509_USER_CERT or the X509_USER_KEY

    X509_USER_PROXY_FILE is used to generate the default
    proxy file name.

    In other words:

    proxy_get_filenames() is used by grid-proxy-init, wgpi, grid-proxy-info and
    Indirectly by gss_acquire_creds. For grid-proxy-init and wgpi, the proxy_in
    is 0, for acquire_creds its 1. This is used to signal how the proxy file is
    to be used, 1 for input 0 for output.

    The logic for output is to use the provided input parameter, registry,
    environment, or default name for the proxy. Wgpi calls this multiple times
    as the options window is updated. The file will be created if needed.

    The logic for input is to use the provided input parameter, registry,
    environment variable. But only use the default file if it exists, is owned
    by the user, and has something in it. But not when run as root.

    Then on input if there is a proxy, the user_cert and user_key are set to
    use the proxy.

    Smart card support using PKCS#11 is controled by the USE_PKCS11 flag.

    If the filename for the user key starts with SC: then it is assumed to be
    of the form SC:card:label where card is the name of a smart card, and label
    is the label of the key on the card. The card must be using Cryptoki
    (PKCS#11) This code has been developed using the DataKey implementation
    under Windows 95.

    This will allow the cert to have the same form, with the same label as well
    in the future.



Parameters:

Returns:
**********************************************************************/

int
proxy_get_filenames(
    int                                 proxy_in,
    char **                             p_cert_file,
    char **                             p_cert_dir,
    char **                             p_user_proxy,
    char **                             p_user_cert,
    char **                             p_user_key)
{

    int                                 status = -1;
    char *                              cert_file = NULL;
    char *                              cert_dir = NULL;
    char *                              user_proxy = NULL;
    char *                              user_cert = NULL;
    char *                              user_key = NULL;
    char *                              home = NULL;
    char *                              default_user_proxy = NULL;
    char *                              default_user_cert = NULL;
    char *                              default_user_key = NULL;
    char *                              default_cert_dir = NULL;
    char *                              installed_cert_dir = NULL;
#ifdef WIN32
    HKEY                                hkDir = NULL;
    char                                val_user_cert[512];
    char                                val_user_key[512];
    char                                val_user_proxy[512];
    char                                val_cert_dir[512];
    char                                val_cert_file[512];
    LONG                                lval;
    DWORD                               type;
#endif

#ifdef WIN32
    RegOpenKey(HKEY_CURRENT_USER,GSI_REGISTRY_DIR,&hkDir);
#endif

    /* setup some default values */
    if (p_cert_dir)
    {
        cert_dir = *p_cert_dir;
    }


    if (!cert_dir)
    {
        cert_dir = (char *)getenv(X509_CERT_DIR);
    }
#ifdef WIN32
    if (!cert_dir)
    {
        lval = sizeof(val_cert_dir)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_dir",0,&type,
                                      val_cert_dir,&lval) == ERROR_SUCCESS))
        {
            cert_dir = val_cert_dir;
        }
    }
#endif
    if (p_cert_file)
    {
        cert_file = *p_cert_file;
    }

    if (!cert_file)
    {
        cert_file = (char *)getenv(X509_CERT_FILE);
    }
#ifdef WIN32
    if (!cert_file)
    {
        lval = sizeof(val_cert_file)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_cert_file",0,&type,
                                      val_cert_file,&lval) == ERROR_SUCCESS))
        {
            cert_file = val_cert_file;
        }
    }
#endif

    if (cert_dir == NULL)
    {

        /*
         * If ~/.globus/certificates exists, then use that
         */
        home = getenv("HOME");
#ifndef WIN32
        /* Under windows use c:\windows as default home */
        if (!home)
        {
            home = "c:\\windows";
        }
#endif /* WIN32 */

        if (home)
        {
            default_cert_dir = snprintf_wrap("%s%s%s",
                    home, FILE_SEPERATOR, X509_DEFAULT_CERT_DIR);

            if (!default_cert_dir)
            {
                PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                goto err;
            }

            if (checkstat(default_cert_dir) != 1)
            {
                /* default_cert_dir exists */
                cert_dir = default_cert_dir;
            }
        }


        /*
         * Now check for host based default directory
         */
        if (!cert_dir)
        {

            if (checkstat(X509_INSTALLED_HOST_CERT_DIR) != 1)
            {
                /* default_cert_dir exists */
                cert_dir = X509_INSTALLED_HOST_CERT_DIR;
            }
        }

        if (!cert_dir)
        {
            /*
             * ...else look for (in order)
             * $GLOBUS_DEPLOY_PATH/share/certificates
             * $GLOBUS_LOCATION/share/certficates
             */
            char *globus_location;


            globus_location = getenv("GLOBUS_DEPLOY_PATH");

            if (!globus_location)
            {
                globus_location = getenv("GLOBUS_LOCATION");
            }

            if (!globus_location)
            {
                globus_location = getenv("GSI_DEPLOY_PATH");
            }

            if (!globus_location)
            {
                globus_location = getenv("GSI_INSTALL_PATH");
            }

            if (globus_location)
            {
                installed_cert_dir = snprintf_wrap("%s%s%s",
                        globus_location,
                        FILE_SEPERATOR,
                        X509_INSTALLED_CERT_DIR);

                if  (!installed_cert_dir)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }

                /*
                 * Previous code always set cert_dir to
                 * default_cert_dir without checking for its
                 * existance, so we'll also skip the existance
                 * check here.
                 */
                cert_dir = installed_cert_dir;
            }
        }

        if (!cert_dir)
        {
            cert_dir = X509_INSTALLED_HOST_CERT_DIR;
        }
    }

    if (cert_dir)
    {
        if (checkstat(cert_dir)  == 1)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERTS);
            ERR_add_error_data(2,"x509_cert_dir=",cert_dir);
            goto err;
        }
    }

    if (cert_file)
    {
        if (checkstat(cert_file)  == 1)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERTS);
            ERR_add_error_data(2,"x509_cert_file=",cert_file);
            goto err;
        }
    }
    /* if X509_USER_PROXY is defined, use it for cert and key,
     * and for additional certs.
     * if not, and the default user_proxy file is present,
     * use it.
     * If not, get the X509_USER_CERT and X509_USER_KEY
     * if not, use ~/.globus/usercert.pem ~/.globus/userkey.pem
     */
    if (p_user_proxy)
    {
        user_proxy = *p_user_proxy;
    }

    if (!user_proxy)
    {
        user_proxy = (char *)getenv(X509_USER_PROXY);
    }
#ifdef WIN32
    if (!user_proxy)
    {
        lval = sizeof(val_user_proxy)-1;
        if (hkDir && (RegQueryValueEx(hkDir,"x509_user_proxy",0,&type,
                                      val_user_proxy,&lval) == ERROR_SUCCESS))
        {
            user_proxy = val_user_proxy;
        }
    }
#endif
    if (!user_proxy && !getenv("X509_RUN_AS_SERVER"))
    {
        default_user_proxy = snprintf_wrap("%s%s%s%lu",
                                           DEFAULT_SECURE_TMP_DIR,
                                           FILE_SEPERATOR,
                                           X509_USER_PROXY_FILE,
                                           getuid());

        if (!default_user_proxy)
        {
            PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
            goto err;
        }

#ifndef WIN32
        if ((!proxy_in || getuid() != 0)
            && checkstat(default_user_proxy) == 0)
#endif
        {
            user_proxy = default_user_proxy;
        }
    }
    if (proxy_in && user_proxy)
    {
        user_cert = user_proxy;
        user_key = user_proxy;
    }
    else
    {
        if (!user_proxy && !proxy_in)
        {
            user_proxy = default_user_proxy;
        }

        if (p_user_cert)
        {
            user_cert = *p_user_cert;
        }

        if(!user_cert)
        {
            user_cert = (char *)getenv(X509_USER_CERT);
        }

#ifdef WIN32
        if (!user_cert)
        {
            lval = sizeof(val_user_cert)-1;
            if (hkDir && (RegQueryValueEx(
                              hkDir,
                              "x509_user_cert",
                              0,
                              &type,
                              val_user_cert,&lval) == ERROR_SUCCESS))
            {
                user_cert = val_user_cert;
            }
        }
#endif
        if (user_cert)
        {
            if (p_user_key)
            {
                user_key = *p_user_key;
            }
            if (!user_key)
            {
                user_key = (char *)getenv(X509_USER_KEY);
            }
#ifdef WIN32
            if (!user_key)
            {
                lval = sizeof(val_user_key)-1;
                if (hkDir && (RegQueryValueEx(
                                  hkDir,
                                  "x509_user_key",
                                  0,
                                  &type,
                                  val_user_key,&lval) == ERROR_SUCCESS))
                {
                    user_key = val_user_key;
                }
            }
#endif
            if (!user_key)
            {
                user_key = user_cert;
            }
        }
        else
        {
#ifndef WIN32
            if (getuid() == 0)
            {
                if (checkstat(X509_DEFAULT_HOST_CERT) != 1)
                {
                    user_cert = X509_DEFAULT_HOST_CERT;
                }
                if (checkstat(X509_DEFAULT_HOST_KEY) != 1)
                {
                    user_key = X509_DEFAULT_HOST_KEY;
                }
            }
            else
#endif
            {
                if (!home)
                {
                    home = getenv("HOME");
                }
                if (!home)
                {
#ifndef WIN32
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_NO_HOME);
                    goto err;
#else
                    home = "c:\\";
#endif
                }

                default_user_cert = snprintf_wrap("%s%s%s",
                        home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT);

                if (!default_user_cert)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }

                default_user_key = snprintf_wrap("%s%s%s",
                        home,FILE_SEPERATOR, X509_DEFAULT_USER_KEY);

                if (!default_user_key)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }

                user_cert = default_user_cert;
                user_key = default_user_key;

                /* Support for pkcs12 credentials. */
                {
                  int fd = open(default_user_cert, O_RDONLY);
                  if (fd >= 0)
                    close(fd);
                  else {
                    /* Cannot open normal file -- look for pkcs12. */
                    char *certname = NULL;

                    free(default_user_cert);
                    free(default_user_key);


                    certname = getenv("X509_USER_CRED");

                    if (!certname) {
                      default_user_cert = snprintf_wrap("%s%s%s",
                              home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT_P12);

                      if (!default_user_cert) {
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                        goto err;
                      }

                      if (checkstat(default_user_cert) != 0) {
                        free(default_user_cert);
                        default_user_cert = snprintf_wrap("%s%s%s",
                                home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT_P12_GT);
                      }

                      if (!default_user_cert) {
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                        goto err;
                      }

                    }
                    else {
                      default_user_cert = strndup(certname, strlen(certname));

                      if (!default_user_cert) {
                        PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                        goto err;
                      }
                    }

                    default_user_key = strndup(default_user_cert, strlen(default_user_cert));

                    if (!default_user_key) {
                      PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                      goto err;
                    }

                    user_cert = default_user_cert;
                    user_key = default_user_key;
                  }
                }
            }
        }
    }

    status = 0;
err:
    if (!status) {
      if (p_cert_file && cert_file && !(*p_cert_file)) {
        *p_cert_file = strdup(cert_file);
      }
      if (p_cert_dir && cert_dir && !(*p_cert_dir)) {
        *p_cert_dir = strdup(cert_dir);
      }
      if (p_user_proxy && user_proxy && !(*p_user_proxy)) {
        *p_user_proxy = strdup(user_proxy);
      }
      if (p_user_cert && user_cert && !(*p_user_cert)) {
        free(*p_user_cert);
        *p_user_cert = strdup(user_cert);
      }
      if (p_user_key && user_key && !(*p_user_key)) {
        free(*p_user_key);
        *p_user_key = strdup(user_key);
      }
    }
#ifdef WIN32
    if (hkDir)
    {
        RegCloseKey(hkDir);
    }
#endif

    free(default_user_proxy);
    free(installed_cert_dir);
    free(default_cert_dir);
    free(default_user_cert);
    free(default_user_key);

    return status;
}
/**********************************************************************
Function: proxy_load_user_cert()

Description:
    loads the users cert. May need a pw callback for Smartcard PIN.
    May use a smartcard too.

Parameters:

Returns:
**********************************************************************/

static int cert_load_pkcs12(BIO *bio, int (*pw_cb)(), X509 **cert, EVP_PKEY **key, STACK_OF(X509) **chain)
{
  PKCS12 *p12 = NULL;
  char *password = NULL;
  char buffer[1024];
  int ret = 0;

  p12 = d2i_PKCS12_bio(bio, NULL);
  if (!p12)
    return 0;

  if (!PKCS12_verify_mac(p12, "", 0)) {

    int sz = 0;

    if (pw_cb)
      sz = pw_cb(buffer, 1024, 0);
    else
      if (EVP_read_pw_string(buffer, 1024, EVP_get_pw_prompt(), 0) != -1)
        sz = strlen(buffer);

    if (sz)
      password = buffer;
    else
      goto err;
  }
  else
    password="";

  ret = PKCS12_parse(p12, password, key, cert, chain);

 err:
  memset(buffer, 0, 1024);

  if (p12)
     PKCS12_free(p12);

  return ret;
}

int PRIVATE proxy_load_user_cert_and_key_pkcs12(const char *user_cert,
                                                X509 **cert,
                                                STACK_OF(X509) **stack,
                                                EVP_PKEY **pkey,
                                                int (*pw_cb) ())
{
  BIO *bio = BIO_new_file(user_cert, "rb");
  int res = cert_load_pkcs12(bio, pw_cb, cert, pkey, stack);
  BIO_free(bio);

  if (res)
    return 1;
  else {
    if (ERR_peek_error() == ERR_PACK(ERR_LIB_PEM,PEM_F_PEM_READ_BIO,PEM_R_NO_START_LINE)) {
      ERR_clear_error();
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_INVALID_CERT);
    }
    else {
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
    }
    ERR_add_error_data(2, "\n        File=", user_cert);
    return 0;
  }
}



int PRIVATE
proxy_load_user_cert(
    const char *                        user_cert,
    X509 **                              certificate,
    UNUSED(int                                 (*pw_cb)()),
    UNUSED(unsigned long *                     hSession))
{
    int                                 status = -1;
    FILE *                              fp;

    /* Check arguments */
    if (!user_cert)
    {
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
      status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;

      ERR_add_error_data(1, "\n        No certificate file found");
      goto err;
    }

    if (!strncmp(user_cert,"SC:",3))
    {
#ifdef USE_PKCS11
        char * cp;
        char * kp;
        int rc;

        cp = user_cert + 3;
        kp = strchr(cp,':');
        if (kp == NULL)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
            ERR_add_error_data(2, "\n        SmartCard reference=",
                               user_cert);
            status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
            goto err;
        }

        kp++; /* skip the : */

        if (*hSession == 0)
        {
            rc = sc_init(hSession, cp, NULL, NULL, CKU_USER, 0);

            if (rc)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
                ERR_add_error_data(
                    1,
                    "\n        Failed to open session to smartcard");
                status = PRXYERR_R_PROCESS_CERT;
                goto err;
            }
        }
        rc = sc_get_cert_obj_by_label(*hSession,kp,
                                      certificate);
        if (rc)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
            ERR_add_error_data(
                2,
                "\n        Could not find certificate on smartcard, label=",
                kp);
            status = PRXYERR_R_PROCESS_CERT;
            goto err;
        }
#else
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
        ERR_add_error_data(
            1,
            "\n       Smartcard support not compiled with this program");
        status = PRXYERR_R_PROCESS_CERT;
        goto err;

        /*
         * DEE? need to add a random number routine here, to use
         * the random number generator on the card
         */

#endif /* USE_PKCS11 */
    }
    else
    {
      if((fp = fopen(user_cert,"rb")) == NULL) {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
        status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;

        ERR_add_error_data(2, "\n        Cert File=", user_cert);
        goto err;
      }

      if (PEM_read_X509(fp,
                        certificate,
                        OPENSSL_PEM_CB(NULL,NULL)) == NULL) {
        if (ERR_peek_error() == ERR_PACK(ERR_LIB_PEM,PEM_F_PEM_READ_BIO,PEM_R_NO_START_LINE)) {
          ERR_clear_error();
          PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_INVALID_CERT);
          status = PRXYERR_R_INVALID_CERT;
        }
        else {
          PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
          status = PRXYERR_R_PROCESS_CERT;
        }

        ERR_add_error_data(2, "\n        File=", user_cert);
        fclose(fp);
        goto err;
      }
      fclose(fp);
    }
    status = 0;
 err:

    return status;
}


/**********************************************************************
Function: proxy_load_user_key()

Description:
    loads the users key. Assumes the cert has been loaded,
    and checks they match.
    May use a smartcard too.

Parameters:

Returns:
    an int specifying the error
**********************************************************************/

int PRIVATE
proxy_load_user_key(
    EVP_PKEY **                         private_key,
    X509 *                              ucert,
    const char *                        user_key,
    int                                 (*pw_cb)(),
    UNUSED(unsigned long *                     hSession))
{
    int                                 status = -1;
    FILE *                              fp;
    EVP_PKEY *                          ucertpkey;
    int                                 (*xpw_cb)();

    if (!private_key)
      return 0;

    xpw_cb = pw_cb;
#ifdef WIN32
    if (!xpw_cb)
    {
        xpw_cb = read_passphrase_win32;
    }
#endif

    /* Check arguments */
    if (!user_key)
    {
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
      status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;

      ERR_add_error_data(1,"\n        No key file found");
      goto err;
    }


    if (!strncmp(user_key,"SC:",3))
    {
#ifdef USE_PKCS11
        char *cp;
        char *kp;
        int rc;

        cp = user_key + 3;
        kp = strchr(cp,':');
        if (kp == NULL)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_KEY_FILE);
            ERR_add_error_data(2,"\n        SmartCard reference=",user_key);
            status = PRXYERR_R_PROBLEM_KEY_FILE;
            goto err;
        }
        kp++; /* skip the : */
        if (*hSession == 0)
        {
            rc = sc_init(hSession, cp, NULL, NULL, CKU_USER, 0);
            if (rc)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
                ERR_add_error_data(
                    1,
                    "\n        Failed to open session to smartcard");
                status = PRXYERR_R_PROCESS_KEY;
                goto err;
            }
        }
        rc = sc_get_priv_key_obj_by_label(hSession,kp,
                                          private_key);
        if (rc)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
            ERR_add_error_data(
                2,
                "\n        Could not find key on smartcard, label=",
                kp);
            status = PRXYERR_R_PROCESS_KEY;
            goto err;
        }
#else
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
        ERR_add_error_data(
            1,
            "\n       Smartcard support not compiled with this program");
        status = PRXYERR_R_PROCESS_KEY;
        goto err;

        /*
         * DEE? could add a random number routine here, to use
         * the random number generator on the card
         */

#endif /* USE_PKCS11 */
    }
    else
    {
      int keystatus;

      if ((fp = fopen(user_key,"rb")) == NULL) {
        PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
        status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;

        ERR_add_error_data(2, "\n        File=",user_key);
        goto err;
      }

      /* user key must be owned by the user, and readable
       * only be the user
       */

      if ((keystatus = checkstat(user_key))) {
        if (keystatus == 4) {
          status = PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE;
          PRXYerr(PRXYERR_F_INIT_CRED,
                  PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE);
        }
        else {
          status = PRXYERR_R_PROBLEM_KEY_FILE;
          PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_KEY_FILE);
        }

        ERR_add_error_data(2, "\n        File=", user_key);
        fclose(fp);
        goto err;
      }

      if (PEM_read_PrivateKey(fp,
                              private_key,
                              OPENSSL_PEM_CB(xpw_cb,NULL)) == NULL) {
        unsigned long error = ERR_peek_error();
        fclose(fp);

#ifdef PEM_F_PEM_DEF_CALLBACK
        if (error == ERR_PACK(ERR_LIB_PEM,
                              PEM_F_PEM_DEF_CALLBACK,
                              PEM_R_PROBLEMS_GETTING_PASSWORD))
#else
          if (error == ERR_PACK(ERR_LIB_PEM,
                                PEM_F_DEF_CALLBACK,
                                PEM_R_PROBLEMS_GETTING_PASSWORD))
#endif
            {
              ERR_clear_error();
            }
#ifdef EVP_F_EVP_DECRYPTFINAL_EX
          else if (error == ERR_PACK(ERR_LIB_EVP,
                                     EVP_F_EVP_DECRYPTFINAL_EX,
                                     EVP_R_BAD_DECRYPT))
#else
          else if (error == ERR_PACK(ERR_LIB_EVP,
                                     EVP_F_EVP_DECRYPTFINAL,
                                     EVP_R_BAD_DECRYPT))
#endif
            {
              ERR_clear_error();
              PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_WRONG_PASSPHRASE);
              status = PRXYERR_R_WRONG_PASSPHRASE;
            }
          else {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
            ERR_add_error_data(2, "\n        File=", user_key);
            status = PRXYERR_R_PROCESS_KEY;
          }
        goto err;
      }
      fclose(fp);
    }

    /*
     * check that the private key matches the certificate
     * Dont want a mixup of keys and certs
     * Will only check rsa type for now.
     */
    if (ucert)
    {
        ucertpkey = X509_get_pubkey(ucert);
        int mismatch = 0;

        if (ucertpkey != NULL
            && EVP_PKEY_base_id(ucertpkey) == EVP_PKEY_base_id(*private_key))
        {
            RSA* public_rsa = EVP_PKEY_get0_RSA(ucertpkey);
            if (public_rsa)
            {
              { /* add in key as random data too */
                BIGNUM const* p;
                BIGNUM const* q;
                RSA_get0_factors(public_rsa, &p, &q);
                if(p != NULL)
                {
                  RAND_add(p, /* awful hack; d is the first field */
                           BN_num_bytes(p),
                           BN_num_bytes(p));
                }
                if (q != NULL)
                {
                  RAND_add(q, BN_num_bytes(q), BN_num_bytes(q));
                }
              }
              {
                BIGNUM const* public_n;
                BIGNUM const* public_e;
                RSA* private_rsa = EVP_PKEY_get0_RSA(*private_key);
                RSA_get0_key(public_rsa, &public_n, &public_e, NULL);
                if (public_n != NULL && private_rsa != NULL)
                {
                  BIGNUM const* private_n;
                  BIGNUM const* private_e;
                  RSA_get0_key(private_rsa, &private_n, &private_e, NULL);
                  if (private_n != NULL && BN_num_bytes(private_n))
                  {
                      if (BN_cmp(public_n, private_n))
                      {
                          mismatch=1;
                      }
                  }
                  else
                  {
                      int ret;
                      BIGNUM* n = BN_dup(public_n);
                      assert(n != NULL && "BN_dup failed");
                      BIGNUM* e = BN_dup(public_e);
                      assert(e != NULL && "BN_dup failed");
                      ret = RSA_set0_key(private_rsa, n, e, NULL);
                      assert(ret == 1 && "RSA_set0_key failed");
                  }
                }
              }
            }
        }
        else
        {
            mismatch=1;
        }

        EVP_PKEY_free(ucertpkey);

        if (mismatch)
        {
            PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_KEY_CERT_MISMATCH);
            status = PRXYERR_R_KEY_CERT_MISMATCH;
            goto err;
        }
    }

    status = 0;

err:
    /* DEE need more cleanup */
    return status;
}


/**********************************************************************
Function: ASN1_UTCTIME_mktime()

Description:
 SSLeay only has compare functions to the current
 So we define a convert to time_t from which we can do differences
 Much of this it taken from the X509_cmp_current_time()
 routine.

Parameters:

Returns:
        time_t
**********************************************************************/

time_t PRIVATE ASN1_TIME_mktime(ASN1_TIME *ctm)
{
  /*
   * note: ASN1_TIME, ASN1_UTCTIME, ASN1_GENERALIZEDTIME are different
   * typedefs of the same type.
   */
  return ASN1_UTCTIME_mktime(ctm);
}

time_t PRIVATE
ASN1_UTCTIME_mktime(
    ASN1_UTCTIME *                      ctm)
{
  char     *str;
  time_t    offset;
  time_t    newtime;
  char      buff1[32];
  char     *p;
  int       i;
  struct tm tm;
  int       size = 0;

  switch (ctm->type) {
  case V_ASN1_UTCTIME:
    size=10;
    break;
  case V_ASN1_GENERALIZEDTIME:
    size=12;
    break;
  }
  p = buff1;
  i = ctm->length;
  str = (char *)ctm->data;
  if ((i < 11) || (i > 17)) {
    return 0;
  }
  memcpy(p,str,size);
  p += size;
  str += size;

  if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
    *(p++)='0'; *(p++)='0';
  }
  else {
    *(p++)= *(str++); *(p++)= *(str++);
  }
  *(p++) = 'Z';
  *p = '\0';

  if (*str == 'Z') {
    offset=0;
  }
  else {
    if ((*str != '+') && (str[5] != '-')) {
      return 0;
    }
    offset=((str[1]-'0')*10+(str[2]-'0'))*60;
    offset+=(str[3]-'0')*10+(str[4]-'0');
    if (*str == '-') {
      offset=-offset;
    }
  }

  tm.tm_isdst = 0;
  int index = 0;
  if (ctm->type == V_ASN1_UTCTIME) {
    tm.tm_year  = (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }
  else {
    tm.tm_year  = (buff1[index++]-'0')*1000;
    tm.tm_year += (buff1[index++]-'0')*100;
    tm.tm_year += (buff1[index++]-'0')*10;
    tm.tm_year += (buff1[index++]-'0');
  }

  if (tm.tm_year < 70) {
    tm.tm_year+=100;
  }

  if (tm.tm_year > 1900) {
    tm.tm_year -= 1900;
  }

  tm.tm_mon   = (buff1[index++]-'0')*10;
  tm.tm_mon  += (buff1[index++]-'0')-1;
  tm.tm_mday  = (buff1[index++]-'0')*10;
  tm.tm_mday += (buff1[index++]-'0');
  tm.tm_hour  = (buff1[index++]-'0')*10;
  tm.tm_hour += (buff1[index++]-'0');
  tm.tm_min   = (buff1[index++]-'0')*10;
  tm.tm_min  += (buff1[index++]-'0');
  tm.tm_sec   = (buff1[index++]-'0')*10;
  tm.tm_sec  += (buff1[index]-'0');

  /*
   * mktime assumes local time, so subtract off
   * timezone, which is seconds off of GMT. first
   * we need to initialize it with tzset() however.
   */

  tzset();
#if defined(HAVE_TIMEGM)
  newtime = (timegm(&tm) + offset*60*60);
#elif defined(HAVE_TIME_T_TIMEZONE)
  newtime = (mktime(&tm) + offset*60*60 - timezone);
#elif defined(HAVE_TIME_T__TIMEZONE)
  newtime = (mktime(&tm) + offset*60*60 - _timezone);
#else
  newtime = (mktime(&tm) + offset*60*60);
#endif

  return newtime;
}


#ifdef CLASS_ADD

/**********************************************************************
Function: proxy_extension_class_add_create()

Description:
            create a X509_EXTENSION for the class_add info.

Parameters:
                A buffer and length. The date is added as
                ANS1_OCTET_STRING to an extension with the
                class_add  OID.

Returns:

**********************************************************************/

X509_EXTENSION PRIVATE *
proxy_extension_class_add_create(
    void *                              buffer,
    size_t                              length)

{
    X509_EXTENSION *                    ex = NULL;
    ASN1_OBJECT *                       class_add_obj = NULL;
    ASN1_OCTET_STRING *                 class_add_oct = NULL;
    int                                 crit = 0;

    if(!(class_add_obj = OBJ_nid2obj(OBJ_txt2nid("CLASSADD"))))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_OID);
        goto err;
    }

    if(!(class_add_oct = ASN1_OCTET_STRING_new()))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
        goto err;
    }

    class_add_oct->data = buffer;
    class_add_oct->length = length;

    if (!(ex = X509_EXTENSION_create_by_OBJ(NULL, class_add_obj,
                                            crit, class_add_oct)))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_CLASS_ADD_EXT);
        goto err;
    }
    class_add_oct = NULL;

    return ex;

err:
    if (class_add_oct)
    {
        ASN1_OCTET_STRING_free(class_add_oct);
    }

    if (class_add_obj)
    {
        ASN1_OBJECT_free(class_add_obj);
    }
    return NULL;
}
#endif


int PRIVATE determine_filenames(char **cacert, char **certdir, char **outfile,
                                 char **certfile, char **keyfile, int noregen)
{
  char *oldoutfile = NULL;

  if (noregen) {
    int modify = 0;

    if (*certfile == NULL && *keyfile == NULL)
      modify = 1;

    if (proxy_get_filenames(0, NULL, NULL, &oldoutfile, certfile, keyfile))
      goto err;

    if (modify) {
      free(*certfile);
      free(*keyfile);
      *certfile = strdup(oldoutfile);
      *keyfile = oldoutfile;
    }
    else
      free(oldoutfile);

    if (proxy_get_filenames(0, cacert, certdir, outfile, certfile, keyfile))
      goto err;
  }
  else if (proxy_get_filenames(0, cacert, certdir, outfile, certfile, keyfile))
    goto err;

  return 1;

err:
  return 0;
}

int load_credentials(const char *certname, const char *keyname,
                     X509 **cert, STACK_OF(X509) **stack, EVP_PKEY **key,
                     int (*callback)())
{
  STACK_OF(X509) *chain = NULL;

  if (!certname)
    return 0;

  unsigned long hSession = 0;

  if (!strncmp(certname, "SC:", 3))
    EVP_set_pw_prompt("Enter card pin:");
  else
    EVP_set_pw_prompt("Enter GRID pass phrase for this identity:");

  if (strcmp(certname + strlen(certname) - 4, ".p12")) {
    if(proxy_load_user_cert(certname, cert, callback, &hSession))
      goto err;

    EVP_set_pw_prompt("Enter GRID pass phrase:");

    if (keyname) {
      if (!strncmp(keyname, "SC:", 3))
        EVP_set_pw_prompt("Enter card pin:");

      if (proxy_load_user_key(key, *cert, keyname, callback, &hSession))
        goto err;
    }

    if (stack && (strncmp(certname, "SC:", 3) && (!keyname || !strcmp(certname, keyname)))) {
      chain = sk_X509_new_null();
      if (proxy_load_user_proxy(chain, certname) < 0)
        goto err;
      *stack = chain;
    }
  }
  else {
    if (!proxy_load_user_cert_and_key_pkcs12(certname, cert, stack, key, callback))
      goto err;
  }

  return 1;

err:
  if (chain)
    sk_X509_pop_free(chain, X509_free);
  if (cert) {
    X509_free(*cert);
    *cert = NULL;
  }
  if (key) {
    EVP_PKEY_free(*key);
    *key = NULL;
  }
  return 0;
}

int PRIVATE load_certificate_from_file(FILE *file, X509 **cert,
                                       STACK_OF(X509) **stack)
{
  BIO *in = NULL;

  if (!cert)
    return 0;

  in = BIO_new_fp(file, BIO_NOCLOSE);

  if (in) {
    *cert = PEM_read_bio_X509(in, NULL, 0, NULL);

    if(!*cert)
      goto err;

    if (stack) {
      *stack = load_chain(in, 0);
      if (!(*stack))
        goto err;
    }
  }
  BIO_free(in);
  return 1;

 err:
  BIO_free(in);
  if (cert)
    X509_free(*cert);
  if (stack)
    sk_X509_pop_free(*stack, X509_free);
  return 0;

}

STACK_OF(X509) *load_chain(BIO *in, char *certfile)
{
  STACK_OF(X509_INFO) *sk=NULL;
  STACK_OF(X509) *stack=NULL, *ret=NULL;
  X509_INFO *xi;
  int first = 1;

  if(!(stack = sk_X509_new_null())) {
    if (certfile)
      printf("memory allocation failure\n");
    goto end;
  }

  /* This loads from a file, a stack of x509/crl/pkey sets */
  if(!(sk=PEM_X509_INFO_read_bio(in,NULL,NULL,NULL))) {
    if (certfile)
      printf("error reading the file, %s\n",certfile);
    goto end;
  }

  /* scan over it and pull out the certs */
  while (sk_X509_INFO_num(sk)) {
    /* skip first cert */
    if (first) {
      first = 0;
      continue;
    }
    xi=sk_X509_INFO_shift(sk);
    if (xi->x509 != NULL) {
      sk_X509_push(stack,xi->x509);
      xi->x509=NULL;
    }
    X509_INFO_free(xi);
  }
  if(!sk_X509_num(stack)) {
    if (certfile)
      printf("no certificates in file, %s\n",certfile);
    sk_X509_free(stack);
    goto end;
  }
  ret=stack;
end:
  sk_X509_INFO_free(sk);
  return(ret);
}

static char hextoint(char r, char s)
{
  int v = 0;
  if (isxdigit(r) && isxdigit(s)) {
    v = hex2num(r);
    v <<= 4;
    v += hex2num(s);
  }
  return v;
}

static unsigned char *reencode_string(unsigned char *string, int *len)
{
  unsigned char *temp = string;
  unsigned char *pos  = string;
  char t = '\0';
  char r = '\0';
  *len = 0;

  while(*string) {
    switch (*string) {
    case '\\':
      t = *++string;

      if (t == '\\') {
        *pos++ = '\\';
        ++(*len);
      }
      else if (isxdigit(t)) {
        r = *++string;
        *pos++ = hextoint(tolower(t), tolower(r));
        ++(*len);
        ++string;
      }
      else {
        *pos++ = t;
        ++(*len);
        ++string;
      }
      break;

    default:
      ++(*len);
      *pos++ = *string++;
      break;
    }
  }

  return temp;
}

static X509_NAME *make_DN(const char *dnstring)
{
  char *buffername = (char*)malloc(strlen(dnstring)+1);
  unsigned char *buffervalue = (unsigned char*)malloc(strlen(dnstring)+1);
  char *currentname;
  unsigned char *currentvalue;
  X509_NAME *name = NULL;
  int valuelen = 0;
  char next = 0;

  name = X509_NAME_new();

  int status = 0; /*
                   * 0 = looking for /type
                   * 1 = looking for value
                   */
  do {
    switch (status) {
    case 0:
      /* Parse for /Name= */
      currentname=buffername;
      while (*dnstring) {
        if (*dnstring == '\\') {
          *currentname++ = *++dnstring;
          if (*dnstring == '\0') {
            break;
          }
          dnstring++;
        }
        else if (*dnstring == '=') {
          *currentname='\0';
          break;
        }
        else if (*dnstring == '\0') {
          break;
        }
        else
          *currentname++ = *dnstring++;
      }
      /* now, if *dnstring == '\0' then error; */

      if (*dnstring == '\0')
        goto err;
      /* else, we got a type, now look for a value. */
      status = 1;
      dnstring++;
      break;
    case 1:
      /* Parse for value */
      currentvalue=buffervalue;
      while (*dnstring) {
        if (*dnstring == '\\') {
          next = *++dnstring;
          if (next == '\0') {
            break;
          }
          else if (next != '/') {
            *currentvalue++ = '\\';
            *currentvalue++ = next;
          }
          else {
            *currentvalue++ = '/';
          }
          dnstring++;
        }
        else if (*dnstring == '/') {
          *currentvalue='\0';
          break;
        }
        else if (*dnstring == '\0') {
          *currentvalue='\0';
          break;
        }
        else
          *currentvalue++ = *dnstring++;
      }

      *currentvalue='\0';
      if (strlen((char*)buffervalue) == 0)
        goto err;

      /* Now we have both type and value.  Add to the X509_NAME_ENTRY */

      buffervalue = reencode_string(buffervalue, &valuelen);

      X509_NAME_add_entry_by_txt(name, buffername+1,  /* skip initial '/' */
                                 V_ASN1_APP_CHOOSE,
                                 buffervalue, valuelen, X509_NAME_entry_count(name),
                                 0);
      status = 0;
      break;
    }
  } while (*dnstring);

  free(buffername);
  free(buffervalue);

  return name;
 err:
  free(buffername);
  free(buffervalue);
  X509_NAME_free(name);

  return NULL;

}

static int check_critical_extensions(X509 *cert, int itsaproxy)
{
  int i = 0;
  ASN1_OBJECT *extension_obj;
  int nid;
  X509_EXTENSION *ex;

  int nid_pci3 = my_txt2nid(PROXYCERTINFO_OLD_OID);
  int nid_pci4 = my_txt2nid(PROXYCERTINFO_OID);

  STACK_OF(X509_EXTENSION) const* extensions = X509_get0_extensions(cert);

  for (i=0; i < sk_X509_EXTENSION_num(extensions); i++) {
    ex = (X509_EXTENSION *) sk_X509_EXTENSION_value(extensions,i);

    if(X509_EXTENSION_get_critical(ex)) {
      extension_obj = X509_EXTENSION_get_object(ex);

      nid = OBJ_obj2nid(extension_obj);

      if (itsaproxy) {
        if (nid != NID_basic_constraints &&
            nid != NID_key_usage &&
            nid != NID_ext_key_usage &&
            nid != NID_netscape_cert_type &&
            nid != NID_subject_key_identifier &&
            nid != NID_authority_key_identifier &&
            nid != nid_pci3 &&
            nid != nid_pci4) {
          return 0;
        }
      }
      else {
        if (nid != NID_basic_constraints &&
            nid != NID_key_usage &&
            nid != NID_ext_key_usage &&
            nid != NID_netscape_cert_type &&
            nid != NID_subject_key_identifier &&
            nid != NID_authority_key_identifier) {
           return 0;
        }
      }
    }
  }
  return 1;
}
