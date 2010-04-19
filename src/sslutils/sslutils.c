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
#include "myproxycertinfo.h"
#include "sslutils.h"
#include "parsertypes.h"

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
extern void free_policies(struct policy **policies);
extern int read_pathrestriction(STACK_OF(X509) *chain, char *path,
                                struct policy ***namespaces, 
                                struct policy ***signings);

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
    {ERR_PACK(0,PRXYERR_F_VERIFY_CB ,0),"verify_callback"},
    {ERR_PACK(0,PRXYERR_F_PROXY_TMP ,0),"proxy_marshal_tmp"},
    {ERR_PACK(0,PRXYERR_F_INIT_CRED ,0),"proxy_init_cred"},
    {ERR_PACK(0,PRXYERR_F_LOCAL_CREATE, 0),"proxy_local_create"},
    {ERR_PACK(0,PRXYERR_F_CB_NO_PW, 0),"proxy_pw_cb"},
    {ERR_PACK(0,PRXYERR_F_GET_CA_SIGN_PATH, 0),"get_ca_signing_policy_path"},
    {ERR_PACK(0,PRXYERR_F_PROXY_SIGN_EXT ,0),"proxy_sign_ext"},
    {ERR_PACK(0,PRXYERR_F_PROXY_CHECK_SUBJECT_NAME,0),
     "proxy_check_subject_name"},
    {ERR_PACK(0,PRXYERR_F_PROXY_CONSTRUCT_NAME ,0),"proxy_construct_name"},
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
    {PRXYERR_R_BAD_PROXY_ISSUER, "proxy can only be signed by user"},
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
    {PRXYERR_R_REMOTE_CRED_EXPIRED, "remote certificate has expired"},
    {PRXYERR_R_USER_CERT_EXPIRED, "user certificate has expired"},
    {PRXYERR_R_SERVER_CERT_EXPIRED, "system certificate has expired"},
    {PRXYERR_R_PROXY_EXPIRED, "proxy expired: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_NO_PROXY, "no proxy credentials: run grid-proxy-init or wgpi first"},
    {PRXYERR_R_CRL_SIGNATURE_FAILURE, "invalid signature on a CRL"},
    {PRXYERR_R_CRL_NEXT_UPDATE_FIELD, "invalid nextupdate field in CRL"},
    {PRXYERR_R_CRL_HAS_EXPIRED, "outdated CRL found, revoking all certs till you get new CRL"},
    {PRXYERR_R_CERT_REVOKED, "certificate revoked per CRL"},
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
    {PRXYERR_R_CB_CALLED_WITH_ERROR,"certificate failed verify:"},
    {PRXYERR_R_CB_ERROR_MSG, "certificate:"},
    {PRXYERR_R_CLASS_ADD_OID,"can't find CLASS_ADD OID"},
    {PRXYERR_R_CLASS_ADD_EXT,"problem adding CLASS_ADD Extension"},
    {PRXYERR_R_DELEGATE_VERIFY,"problem verifiying the delegate extension"},
    {PRXYERR_R_EXT_ADD,"problem adding extension"},
    {PRXYERR_R_DELEGATE_CREATE,"problem creating delegate extension"},
    {PRXYERR_R_DELEGATE_COPY,"problem copying delegate extension to proxy"},
    {PRXYERR_R_BUFFER_TOO_SMALL,"buffer too small"},
    {PRXYERR_R_CERT_NOT_YET_VALID,"remote certificate not yet valid"},
    {PRXYERR_R_LOCAL_CA_UNKNOWN,"cannot find CA certificate for local credential"},
    {PRXYERR_R_OUT_OF_MEMORY,"out of memory"},
    {PRXYERR_R_BAD_ARGUMENT,"bad argument"},
    {PRXYERR_R_BAD_MAGIC,"bad magic number"},
    {PRXYERR_R_UNKNOWN_CRIT_EXT,"unable to handle critical extension"},
    {0,NULL}
};

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

    if (sk_X509_NAME_ENTRY_num(a->entries) !=
        sk_X509_NAME_ENTRY_num(b->entries))
    {
        return(sk_X509_NAME_ENTRY_num(a->entries) -
               sk_X509_NAME_ENTRY_num(b->entries));
    }
    
    for (i=sk_X509_NAME_ENTRY_num(a->entries)-1; i>=0; i--)
    {
        na = sk_X509_NAME_ENTRY_value(a->entries,i);
        nb = sk_X509_NAME_ENTRY_value(b->entries,i);
        j = na->value->length-nb->value->length;

        if (j)
        {
            return(j);
        }
        
        j = memcmp(na->value->data,
                   nb->value->data,
                   na->value->length);
        if (j)
        {
            return(j);
        }
    }

    /* We will check the object types after checking the values
     * since the values will more often be different than the object
     * types. */
    for (i=sk_X509_NAME_ENTRY_num(a->entries)-1; i>=0; i--)
    {
        na = sk_X509_NAME_ENTRY_value(a->entries,i);
        nb = sk_X509_NAME_ENTRY_value(b->entries,i);
        j = OBJ_cmp(na->object,nb->object);

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
    char *                              egd_path;
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
        
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.1","CLASSADD","ClassAdd");
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.2","DELEGATE","Delegate");
        OBJ_create("1.3.6.1.4.1.3536.1.1.1.3","RESTRICTEDRIGHTS",
                   "RestrictedRights");
        OBJ_create("0.9.2342.19200300.100.1.1","USERID","userId");

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

        if (randfile)
        {
            RAND_load_file(randfile,1024L*1024L);
        }

#if SSLEAY_VERSION_NUMBER >=  0x0090581fL
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

/***********************************************************************
Function: proxy_cred_desc_new()

Description:
        alloc a new proxy_cred_desc
*********************************************************************/

proxy_cred_desc PRIVATE *
proxy_cred_desc_new() 
{
    proxy_cred_desc *                   pcd;

    pcd = (proxy_cred_desc *)malloc(sizeof(proxy_cred_desc));
    
    if (pcd)
    {
        pcd->ucert = NULL;
        pcd->upkey = NULL;
        pcd->cert_chain = NULL;
        pcd->gs_ctx = NULL;
        pcd->hSession = 0;
        pcd->hPrivKey = 0;
        pcd->certdir = NULL;
        pcd->certfile = NULL;
        pcd->num_null_enc_ciphers = 0;
        pcd->type = CRED_TYPE_PERMANENT;
        pcd->owner = CRED_OWNER_USER;
    }
    
    return pcd;
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
    const char *                        file,
    BIO *                               bp)
{

    int                                 ret = -1;
    BIO *                               in = NULL;
    int                                 i;
    int                                 count=0;
    X509 *                              x = NULL;

    if (bp)
    {
        in = bp;
    }
    else
    {
        if (file == NULL)
        {
            return(1);
        }
        in = BIO_new(BIO_s_file());
    }

    if ((in == NULL) || (!bp && BIO_read_filename(in,file) <= 0))
    {
        X509err(PRXYERR_F_PROXY_LOAD, PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    for (;;)
    {
        x = PEM_read_bio_X509(in,NULL, OPENSSL_PEM_CB(NULL,NULL));
        if (x == NULL)
        {
            if ((ERR_GET_REASON(ERR_peek_error()) ==
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

        if (bp || count)
        {
            i = sk_X509_insert(cert_chain,x,sk_X509_num(cert_chain));

            x = NULL;
        }
        
        count++;

        if (x)
        {
            X509_free(x);
            x = NULL;
        }
    }
    ret = count;
        
err:
    if (x != NULL)
    {
        X509_free(x);
    }
    
    if (!bp && in != NULL)
    {
        BIO_free(in);
    }
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
    int                                 (*callback)())

{
    RSA *                               rsa = NULL;
    EVP_PKEY *                          pkey = NULL;
    EVP_PKEY *                          upkey = NULL;
    X509_NAME *                         name = NULL; 
    X509_REQ *                          req = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    int                                 rbits;

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
        
        if (upkey->type != EVP_PKEY_RSA)
        {
            PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
            goto err;
        }
        
        rbits = 8 * EVP_PKEY_size(upkey);
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

    /*
     * Note: The cast of the callback function is consistent with
     * the declaration of RSA_generate_key() in OpenSSL.  It may
     * trigger a warning if you compile with SSLeay.
     */
    if ((rsa = RSA_generate_key(rbits,
                                RSA_F4,
                                (void (*)(int,int,void *))callback
                                ,NULL)) == NULL)
    {
        PRXYerr(PRXYERR_F_PROXY_GENREQ,PRXYERR_R_PROCESS_PROXY_KEY);
        goto err;
    }
    
    if (!EVP_PKEY_assign_RSA(pkey,rsa))
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

    if (!X509_REQ_sign(req,pkey,EVP_sha1()))
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
    EVP_PKEY *                          user_public_key;
    X509_NAME *                         subject_name = NULL;
    X509_NAME *                         issuer_name = NULL;
    int                                 rc = 0;

    unsigned char                       md[SHA_DIGEST_LENGTH];
    unsigned int                        len;
    unsigned int                        dig_len = -1;
    long                                sub_hash;

    if(proxyver>=3) {

      user_public_key = X509_get_pubkey(user_cert);
#ifdef TYPEDEF_I2D_OF
      ASN1_digest((i2d_of_void*)i2d_PUBKEY, EVP_sha1(), (char *) user_public_key, md, &len);
#else
      ASN1_digest(i2d_PUBKEY, EVP_sha1(), (char *) user_public_key, md, &len);
#endif
      EVP_PKEY_free(user_public_key);

      sub_hash = md[0] + (md[1] + (md[2] + (md[3] >> 1) * 256) * 256) * 256;
 
      newcn = malloc(sizeof(long)*4 + 1);
      sprintf(newcn, "%ld", sub_hash);
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
                              newcn, dig_len)) {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_PROCESS_SIGN);
        if (proxyver >= 3)
          free(newcn);
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
                      EVP_sha1(), 
                      req,
                      new_cert,
                      subject_name,
                      issuer_name,
                      seconds,
                      0,
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

    if (proxyver >= 3)
      free(newcn);

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
    int                       serial_num,
    STACK_OF(X509_EXTENSION) *extensions,
    int                       proxyver,
    int                       pastproxy,
    const char               *newserial,
    int                       selfsigned)
{
    EVP_PKEY *                          new_public_key = NULL;
    EVP_PKEY *                          tmp_public_key = NULL;
    X509_CINF *                         new_cert_info;
    X509_CINF *                         user_cert_info;
    X509_EXTENSION *                    extension = NULL;
    time_t                              time_diff, time_now, time_after;
    ASN1_UTCTIME *                      asn1_time = NULL;
    int                                 i;
    unsigned char                       md[SHA_DIGEST_LENGTH];
    unsigned int                        len;

    if (!selfsigned)
      user_cert_info = user_cert->cert_info;

    *new_cert = NULL;
    
    if ((req->req_info == NULL) ||
        (req->req_info->pubkey == NULL) ||
        (req->req_info->pubkey->public_key == NULL) ||
        (req->req_info->pubkey->public_key->data == NULL))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN,PRXYERR_R_MALFORM_REQ);
        goto err;
    }
    
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

    new_cert_info = (*new_cert)->cert_info;

    /* set the subject name */

    if(subject_name && !X509_set_subject_name(*new_cert,subject_name))
    {
        PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
        goto err;
    }

    /* DEE? will use same serial number, this may help
     * with revocations, or may cause problems.
     */

    if (serial_num)
      ASN1_INTEGER_set(X509_get_serialNumber(*new_cert), serial_num);
    else {
      if (newserial) {
        BIGNUM *bn = NULL;
        if (BN_hex2bn(&bn, newserial) != 0) {
          ASN1_INTEGER *a_int = BN_to_ASN1_INTEGER(bn, NULL);
          ASN1_INTEGER_free((*new_cert)->cert_info->serialNumber);

          /* Note:  The a_int == NULL case is handled below. */
          (*new_cert)->cert_info->serialNumber = a_int;
          BN_free(bn);
        }
      }
      else if (proxyver > 2) {
        ASN1_INTEGER_free(X509_get_serialNumber(*new_cert));
          
        new_public_key = X509_REQ_get_pubkey(req);
#ifdef TYPEDEF_I2D_OF
        ASN1_digest((i2d_of_void*)i2d_PUBKEY, EVP_sha1(), (char *) new_public_key, md, &len);
#else
        ASN1_digest(i2d_PUBKEY, EVP_sha1(), (char *) new_public_key, md, &len);
#endif
        new_public_key = NULL;

        (*new_cert)->cert_info->serialNumber = ASN1_INTEGER_new();
        (*new_cert)->cert_info->serialNumber->length = len;
        (*new_cert)->cert_info->serialNumber->data   = malloc(len);

        if (!((*new_cert)->cert_info->serialNumber->data)) {
          PRXYerr(PRXYERR_F_PROXY_SIGN_EXT, PRXYERR_R_PROCESS_PROXY);
          goto err;
        }
        memcpy((*new_cert)->cert_info->serialNumber->data, md, SHA_DIGEST_LENGTH);

      } 
      else if (selfsigned) {
        ASN1_INTEGER *copy = ASN1_INTEGER_new();
        if (copy) {
          ASN1_INTEGER_set(copy, 1);
          ASN1_INTEGER_free((*new_cert)->cert_info->serialNumber);

        (*new_cert)->cert_info->serialNumber = copy;
        }
        else
          goto err;
      }
      else {
        ASN1_INTEGER *copy = ASN1_INTEGER_dup(X509_get_serialNumber(user_cert));
        ASN1_INTEGER_free((*new_cert)->cert_info->serialNumber);

        /* Note:  The copy == NULL case is handled immediately below. */
        (*new_cert)->cert_info->serialNumber = copy;
      }
    }

    if (!(*new_cert)->cert_info->serialNumber) {
      PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
      goto err;
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
        X509_set_notAfter(*new_cert, user_cert_info->validity->notAfter);
      }
    }

    /* transfer the public key from req to new cert */
    /* DEE? should this be a dup? */

    X509_PUBKEY_free(new_cert_info->key);
    new_cert_info->key = req->req_info->pubkey;
    req->req_info->pubkey = NULL;

    /*
     * We can now add additional extentions here
     * such as to control the usage of the cert
     */

    if (new_cert_info->version == NULL)
    {
        if ((new_cert_info->version = ASN1_INTEGER_new()) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_PROCESS_PROXY);
            goto err;
        }
    }

    ASN1_INTEGER_set(new_cert_info->version,2); /* version 3 certificate */

    /* Free the current entries if any, there should not
     * be any I belive 
     */
    
    if (new_cert_info->extensions != NULL)
    {
        sk_X509_EXTENSION_pop_free(new_cert_info->extensions,
                                   X509_EXTENSION_free);
    }
        
    /* Add extensions provided by the client */

    if (extensions)
    {
        if ((new_cert_info->extensions =
             sk_X509_EXTENSION_new_null()) == NULL)
        {
            PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
        }

        /* Lets 'copy' the client extensions to the new proxy */
        /* we should look at the type, and only copy some */

        for (i=0; i<sk_X509_EXTENSION_num(extensions); i++)
        {
            extension = X509_EXTENSION_dup(
                sk_X509_EXTENSION_value(extensions,i));

            if (extension == NULL)
            {
                PRXYerr(PRXYERR_F_PROXY_SIGN_EXT,PRXYERR_R_DELEGATE_COPY);
                goto err;
            }
            
            if (!sk_X509_EXTENSION_push(new_cert_info->extensions,
                                        extension))
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
    int                                 i;
    X509 *                              cert;

    if (!PEM_write_bio_X509(bp,ncert))
    {
        return 1;
    }

    if (!PEM_write_bio_RSAPrivateKey(bp,
                                     npkey->pkey.rsa,
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
    if (pvd->cert_chain)
    {
        sk_X509_pop_free(pvd->cert_chain,X509_free);
    }
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
    /*
     * OpenSSL-0.9.6 has a  check_issued routine which
     * we want to override so we  can replace some of the checks.
     */

    ctx->check_issued = proxy_check_issued;
    return X509_verify_cert(ctx);
}
#endif

/* Ifdef out all extra code not needed for k5cert
 * This includes the OLDGAA
 */

#ifndef BUILD_FOR_K5CERT_ONLY
/**********************************************************************
Function: proxy_check_proxy_name()

Description:
    Check if the subject name is a proxy, and the issuer name
        is the same as the subject name, but without the proxy
    entry. 
        i.e. inforce the proxy signing requirement of 
        only a user or a user's proxy can sign a proxy. 
        Also pass back Rif this is a limited proxy. 

Parameters:

Returns:
        -1  if there was an error
         0  if not a proxy
         1  if a proxy
         2  if a limited proxy

*********************************************************************/

int proxy_check_proxy_name(
    X509 *                              cert)
{
    int                                 ret = 0;
    X509_NAME *                         subject;
    X509_NAME *                         name = NULL;
    X509_NAME_ENTRY *                   ne = NULL;
    ASN1_STRING *                       data;
    int nidv3, nidv4 = 0;
    int indexv3 = -1, indexv4 = -1;

    ASN1_OBJECT *objv3;
    ASN1_OBJECT *objv4;

    objv3 = OBJ_txt2obj(PROXYCERTINFO_V3,1);
    objv4 = OBJ_txt2obj(PROXYCERTINFO_V4,1);
    nidv3 = OBJ_obj2nid(objv3);
    nidv4 = OBJ_obj2nid(objv4);

    ASN1_OBJECT_free(objv3);
    ASN1_OBJECT_free(objv4);

    if (nidv3 == 0 || nidv4 == 0)
      ERR_clear_error();

    indexv3 = X509_get_ext_by_NID(cert, nidv3, -1);
    indexv4 = X509_get_ext_by_NID(cert, nidv4, -1);

    if (indexv3 != -1 || indexv4 != -1) {
      /* Its a proxy! */
      X509_EXTENSION *ext = X509_get_ext(cert, (indexv3 == -1 ? indexv4 : indexv3));

      if (ext) {
        myPROXYCERTINFO *certinfo = NULL;

        certinfo = (myPROXYCERTINFO *)X509V3_EXT_d2i(ext);

        if (certinfo) {
          myPROXYPOLICY *policy = myPROXYCERTINFO_get_proxypolicy(certinfo);

          if (policy) {
            ASN1_OBJECT *policylang;
            policylang = myPROXYPOLICY_get_policy_language(policy);

            /* TO DO:  discover exact type of proxy. */

          }
        }
#if OPENSSL_VERSION_NUMBER >= 0x00908010
#ifdef EXFLAG_PROXY
        cert->ex_flags |= EXFLAG_PROXY;
#endif
#endif
        return 1;
      }
    }
    subject = X509_get_subject_name(cert);
    ne = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject)-1);
    
    if (!OBJ_cmp(ne->object,OBJ_nid2obj(NID_commonName)))
    {
        data = X509_NAME_ENTRY_get_data(ne);
        if ((data->length == 5 && 
             !memcmp(data->data,"proxy",5)) || 
            (data->length == 13 && 
             !memcmp(data->data,"limited proxy",13)))
        {
        
            if (data->length == 13)
            {
                ret = 2; /* its a limited proxy */
            }
            else
            {
                ret = 1; /* its a proxy */
            }
            /*
             * Lets dup the issuer, and add the CN=proxy. This should
             * match the subject. i.e. proxy can only be signed by
             * the owner.  We do it this way, to double check
             * all the ANS1 bits as well.
             */

            /* DEE? needs some more err processing here */

            name = X509_NAME_dup(X509_get_issuer_name(cert));
            ne = X509_NAME_ENTRY_create_by_NID(NULL,
                                               NID_commonName,
                                               V_ASN1_APP_CHOOSE,
                                               (ret == 2) ?
                                               (unsigned char *)
                                               "limited proxy" :
                                               (unsigned char *)"proxy",
                                               -1);

            X509_NAME_add_entry(name,ne,X509_NAME_entry_count(name),0);
            X509_NAME_ENTRY_free(ne);
            ne = NULL;

            if (X509_NAME_cmp_no_set(name,subject))
            {
                /*
                 * Reject this certificate, only the user
                 * may sign the proxy
                 */
                ret = -1;
            }
            X509_NAME_free(name);
        }
    }

#if OPENSSL_VERSION_NUMBER >= 0x00908010
#ifdef EXFLAG_PROXY
    if (ret > 0) {
      cert->ex_flags |= EXFLAG_PROXY;
      if (ret == 1)
        cert->ex_pcpathlen = -1; /* unlimited */
      else if (ret == 2)
        cert->ex_pcpathlen = 0; /* Only at top level if limited */
    }
#endif
#endif

    return ret;
}

#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
/**********************************************************************
 Function: proxy_check_issued()

Description:
        Replace the OpenSSL check_issued in x509_vfy.c with our own,
        so we can override the key usage checks if its a proxy. 
        We are only looking for X509_V_ERR_KEYUSAGE_NO_CERTSIGN

Parameters:r
        See OpenSSL check_issued

Returns:
        See OpenSSL check_issued

**********************************************************************/

int PRIVATE
proxy_check_issued(
    UNUSED(X509_STORE_CTX *                    ctx),
    X509 *                              x,
    X509 *                              issuer)
{
    int                                 ret;
    int                                 ret_code = 1;
        
    ret = X509_check_issued(issuer, x);
    if (ret != X509_V_OK)
    {
        ret_code = 0;
        switch (ret)
        {
        case X509_V_ERR_AKID_SKID_MISMATCH:
            /* 
             * If the proxy was created with a previous version of Globus
             * where the extensions where copied from the user certificate
             * This error could arise, as the akid will be the wrong key
             * So if its a proxy, we will ignore this error.
             * We should remove this in 12/2001 
             * At which time we may want to add the akid extension to the proxy.
             */

        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            /*
             * If this is a proxy certificate then the issuer
             * does not need to have the key_usage set.
             * So check if its a proxy, and ignore
             * the error if so. 
             */
            if (proxy_check_proxy_name(x) >= 1)
            {
                ret_code = 1;
            }
            break;
        default:
            break;
        }
    }
    return ret_code;
}
#endif

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
    X509_OBJECT                         obj;
    X509 *                              cert = NULL;
    X509_CRL *                          crl;
    X509_CRL_INFO *                     crl_info;
    X509_REVOKED *                      revoked;
    STACK_OF(X509_EXTENSION) *          extensions;
    X509_EXTENSION *                    ex;
    ASN1_OBJECT *                       extension_obj;
    int                                 nid;
    char *                              s = NULL;
    SSL *                               ssl = NULL;
    proxy_verify_desc *                 pvd;
    int                                 itsaproxy = 0;
    int                                 i;
    int                                 n;
    int                                 ret;
    time_t                              goodtill;
    char *                              ca_policy_file_path = NULL;
    char *                              cert_dir            = NULL;
    EVP_PKEY *key = NULL;
    int       objset = 0;

    /*
     * If we are being called recursivly to check delegate
     * cert chains, or being called by the grid-proxy-init,
     * a pointer to a proxy_verify_desc will be 
     * pased in the store.  If we are being called by SSL,
     * by a roundabout process, the app_data of the ctx points at
     * the SSL. We have saved a pointer to the  context handle
     * in the SSL, and its magic number should be PVD_MAGIC_NUMBER 
     */
    if (!(pvd = (proxy_verify_desc *)
         X509_STORE_CTX_get_ex_data(ctx,
                                    PVD_STORE_EX_DATA_IDX)))
    {
        ssl = (SSL *)X509_STORE_CTX_get_app_data(ctx);
        pvd = (proxy_verify_desc *)SSL_get_ex_data(ssl,
                                                   PVD_SSL_EX_DATA_IDX);
    }

    /*
     * For now we hardcode the ex_data. We could look at all 
     * ex_data to find ours. 
     * Double check that we are indeed pointing at the context
     * handle. If not, we have an internal error, SSL may have changed
     * how the callback and app_data are handled
     */

    if(pvd->magicnum != PVD_MAGIC_NUMBER)
    {
        PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_BAD_MAGIC);
        return(0);
    }

    /*
     * We now check for some error conditions which
     * can be disregarded. 
     */
        
    if (!ok)
    {
        switch (ctx->error)
        {
#if SSLEAY_VERSION_NUMBER >=  0x0090581fL
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

#endif
        case X509_V_ERR_INVALID_CA:
          /*
           * This may happen since proxy issuers are not CAs
           */
          if (proxy_check_proxy_name(ctx->cert) >= 1) {
            if (proxy_check_issued(ctx, ctx->cert, ctx->current_cert)) {
              ok = 1;
            }
          }
          break;

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_CERT_UNTRUSTED:
          if (proxy_check_proxy_name(ctx->current_cert) > 0) {
            /* Server side, needed to fully recognize a proxy. */
            ok = 1;
          }
          break;

#ifdef X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED
        case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
          /* Proxies ARE allowed */
          ok = 1;
          break;
#endif

        default:
            break;
        }                       
        /* if already failed, skip the rest, but add error messages */
        if (!ok)
        {
            if (ctx->error==X509_V_ERR_CERT_NOT_YET_VALID)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CERT_NOT_YET_VALID);
                ERR_set_continue_needed();
            }
            else if (ctx->error==X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_LOCAL_CA_UNKNOWN); 
                ERR_set_continue_needed();
            }
            else if (ctx->error==X509_V_ERR_CERT_HAS_EXPIRED)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_REMOTE_CRED_EXPIRED); 
                ERR_set_continue_needed();
            }

            goto fail_verify;
        }
        ctx->error = 0;
        return(ok);
    }

    /* 
     * All of the OpenSSL tests have passed and we now get to 
     * look at the certificate to verify the proxy rules, 
     * and ca-signing-policy rules. We will also do a CRL check
     */

    /*
     * Test if the name ends in CN=proxy and if the issuer
     * name matches the subject without the final proxy. 
     */
        
    ret = proxy_check_proxy_name(ctx->current_cert);
    if (ret < 0)
    {
        PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_BAD_PROXY_ISSUER);
        ERR_set_continue_needed();
        ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
        goto fail_verify;
    }
    if (ret > 0)
    {  /* Its a proxy */
        if (ret == 2)
        {
            /*
             * If its a limited proxy, it means it use has been limited 
             * during delegation. It can not sign other certs i.e.  
             * it must be the top cert in the chain. 
             * Depending on who we are, 
             * We may want to accept this for authentication. 
             * 
             *   Globus gatekeeper -- don't accept
             *   sslk5d accept, but should check if from local site.
             *   globus user-to-user Yes, thats the purpose 
             *    of this cert. 
             *
             * We will set the limited_proxy flag, to show we found
             * one. A Caller can then reject. 
             */

            pvd->limited_proxy = 1; /* its a limited proxy */

            if (ctx->error_depth && !pvd->multiple_limited_proxy_ok)
            {
                /* tried to sign a cert with a limited proxy */
                /* i.e. there is still another cert on the chain */
                /* indicating we are trying to sign it! */
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_LPROXY_MISSED_USED);
                ERR_set_continue_needed();
                ctx->error = X509_V_ERR_CERT_SIGNATURE_FAILURE;
                goto fail_verify;
            }
        }

        pvd->proxy_depth++;
        itsaproxy = 1;
    }

    if (!itsaproxy)
    {
                        
#ifdef X509_V_ERR_CERT_REVOKED
        /* 
         * SSLeay 0.9.0 handles CRLs but does not check them. 
         * We will check the crl for this cert, if there
         * is a CRL in the store. 
         * If we find the crl is not valid, we will fail, 
         * as once the sysadmin indicates that CRLs are to 
         * be checked, he best keep it upto date. 
         * 
         * When future versions of SSLeay support this better,
         * we can remove these tests. 
         * we come through this code for each certificate,
         * starting with the CA's We will check for a CRL
         * each time, but only check the signature if the
         * subject name matches, and check for revoked
         * if the issuer name matches.
         * this allows the CA to revoke its own cert as well. 
         */
        
        if (X509_STORE_get_by_subject(ctx,
                                      X509_LU_CRL, 
                                      X509_get_subject_name(ctx->current_cert),
                                      &obj))
        {
            objset = 1;
            crl =  obj.data.crl;
            crl_info = crl->crl;
            /* verify the signature on this CRL */

            key = X509_get_pubkey(ctx->current_cert);
            if (X509_CRL_verify(crl, key) <= 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_SIGNATURE_FAILURE);
                ERR_set_continue_needed();
                ctx->error = X509_V_ERR_CRL_SIGNATURE_FAILURE;
                goto fail_verify;
            }

            /* Check date see if expired */

            i = X509_cmp_current_time(crl_info->nextUpdate);
            if (i == 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_NEXT_UPDATE_FIELD);
                ERR_set_continue_needed();                
                ctx->error = X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
                goto fail_verify;
            }
           

            if (i < 0)
            {
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CRL_HAS_EXPIRED);
                ERR_set_continue_needed();
                ctx->error = X509_V_ERR_CRL_HAS_EXPIRED;
                goto fail_verify;
            }

            /* check if this cert is revoked */


            n = sk_X509_REVOKED_num(crl_info->revoked);
            for (i=0; i<n; i++)
            {
                revoked = (X509_REVOKED *)sk_X509_REVOKED_value(
                    crl_info->revoked,i);

                if(!ASN1_INTEGER_cmp(revoked->serialNumber,
                                     X509_get_serialNumber(ctx->current_cert)))
                {
                    long serial;
                    char buf[256];
                    PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CERT_REVOKED);
                    serial = ASN1_INTEGER_get(revoked->serialNumber);
                    sprintf(buf,"%ld (0x%lX)",serial,serial);
                    s = X509_NAME_oneline(X509_get_subject_name(
                                              ctx->current_cert),NULL,0);
                    
                    ERR_add_error_data(4,"Serial number = ",buf,
                                       " Subject=",s);

                    ctx->error = X509_V_ERR_CERT_REVOKED;
                    ERR_set_continue_needed();
                    free(s);
                    s = NULL;
                    goto fail_verify;
                }
            }
        }
#endif /* X509_V_ERR_CERT_REVOKED */

        /* Do not need to check self signed certs against ca_policy_file */

        if (X509_NAME_cmp(X509_get_subject_name(ctx->current_cert),
                          X509_get_issuer_name(ctx->current_cert)))
        {
            cert_dir = pvd->pvxd->certdir ? pvd->pvxd->certdir :
                getenv(X509_CERT_DIR);

            {
                char * error_string = NULL;
                struct policy **signings   = NULL;
                struct policy **namespaces = NULL;
                int result = SUCCESS_UNDECIDED;

                read_pathrestriction(ctx->chain, cert_dir, &namespaces, &signings);

                result = restriction_evaluate(ctx->chain, namespaces, signings);
                
                free_policies(namespaces);
                free_policies(signings);

                if (result != SUCCESS_PERMIT)
                {
                    PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_CA_POLICY_VIOLATION);

                    ctx->error = X509_V_ERR_INVALID_PURPOSE; 
                                
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
        } /* end of do not check self signed certs */
    }

    /*
     * We want to determine the minimum amount of time
     * any certificate in the chain is good till
     * Will be used for lifetime calculations
     */

    goodtill = ASN1_UTCTIME_mktime(X509_get_notAfter(ctx->current_cert));
    if (pvd->pvxd->goodtill == 0 || goodtill < pvd->pvxd->goodtill)
    {
        pvd->pvxd->goodtill = goodtill;
    }
        
    /* We need to make up a cert_chain if we are the server. 
     * The ssl code does not save this as I would expect. 
     * This is used to create a new proxy by delegation. 
     */

    if (pvd->cert_chain == NULL)
    {
        pvd->cert_chain = sk_X509_new_null();
    }
    
    sk_X509_push(pvd->cert_chain, X509_dup(ctx->current_cert));

    pvd->cert_depth++;

    if (ca_policy_file_path != NULL)
    {
        free(ca_policy_file_path);
    }

    extensions = ctx->current_cert->cert_info->extensions;

    for (i=0;i<sk_X509_EXTENSION_num(extensions);i++)
    {
        ex = (X509_EXTENSION *) sk_X509_EXTENSION_value(extensions,i);

        if(X509_EXTENSION_get_critical(ex))
        {
            extension_obj = X509_EXTENSION_get_object(ex);

            nid = OBJ_obj2nid(extension_obj);

            if (itsaproxy) {
              if (nid != NID_basic_constraints &&
                  nid != NID_key_usage &&
                  nid != NID_ext_key_usage &&
                  nid != NID_netscape_cert_type &&
                  nid != NID_subject_key_identifier &&
                  nid != NID_authority_key_identifier &&
                  nid != OBJ_obj2nid(OBJ_txt2obj(PROXYCERTINFO_V3,1)) &&
                  nid != OBJ_obj2nid(OBJ_txt2obj(PROXYCERTINFO_V4,1)))
                {
                  PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_UNKNOWN_CRIT_EXT);
                  ctx->error = X509_V_ERR_CERT_REJECTED;
                  goto fail_verify;
                }
            }
            else {
              if (nid != NID_basic_constraints &&
                  nid != NID_key_usage &&
                  nid != NID_ext_key_usage &&
                  nid != NID_netscape_cert_type &&
                  nid != NID_subject_key_identifier &&
                  nid != NID_authority_key_identifier)
                {
                  PRXYerr(PRXYERR_F_VERIFY_CB, PRXYERR_R_UNKNOWN_CRIT_EXT);
                  ctx->error = X509_V_ERR_CERT_REJECTED;
                  goto fail_verify;
                }
            }
        }
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

    if(ctx->current_cert == ctx->cert)
    {
        for (i=0; i < sk_X509_num(ctx->chain); i++)
        {
            cert = sk_X509_value(ctx->chain,i);
            if (((i - pvd->proxy_depth) > 1) && (cert->ex_pathlen != -1)
                && ((i - pvd->proxy_depth) > (cert->ex_pathlen + 1))
                && (cert->ex_flags & EXFLAG_BCONS)) 
            {
                ctx->current_cert = cert; /* point at failing cert */
                ctx->error = X509_V_ERR_PATH_LENGTH_EXCEEDED;
                goto fail_verify;
            }
        }
    }

    EVP_PKEY_free(key);

    if (objset)
      X509_OBJECT_free_contents(&obj);

    return(ok);

fail_verify:

    if (key)
      EVP_PKEY_free(key);

    if (objset)
      X509_OBJECT_free_contents(&obj);

    if (ctx->current_cert)
    {
        char *subject_s = NULL;
        char *issuer_s = NULL;
                
        subject_s = X509_NAME_oneline(
            X509_get_subject_name(ctx->current_cert),NULL,0);
        issuer_s = X509_NAME_oneline(
            X509_get_issuer_name(ctx->current_cert),NULL,0);
        
        switch (ctx->error)
        {
            case X509_V_OK:
            case X509_V_ERR_INVALID_PURPOSE:
            case X509_V_ERR_APPLICATION_VERIFICATION:
                 PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CB_ERROR_MSG);
                 ERR_add_error_data(6, 
                    "\n        File=", 
                    ca_policy_file_path ? ca_policy_file_path : "UNKNOWN",
                    "\n        subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
            break;
            case X509_V_ERR_CERT_NOT_YET_VALID:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            case X509_V_ERR_CERT_HAS_EXPIRED:
                 PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CB_ERROR_MSG);
                 ERR_add_error_data(4, 
                    "\n        subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
            break;
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                 PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CA_UNKNOWN);
                    ERR_add_error_data(2, "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
            break;

            default:
                PRXYerr(PRXYERR_F_VERIFY_CB,PRXYERR_R_CB_CALLED_WITH_ERROR);
                ERR_add_error_data(6,"\n        error =",
                    X509_verify_cert_error_string(ctx->error),
                    "\n        subject=",
                    subject_s ? subject_s : "UNKNOWN",
                    "\n        issuer =",
                    issuer_s ? issuer_s : "UNKNOWN");
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
    int                                 i;
    int                                 j;
    int                                 retval = 0;
    X509_STORE *                        cert_store = NULL;
    X509_LOOKUP *                       lookup = NULL;
    X509_STORE_CTX                      csc;
    X509 *                              xcert = NULL;
    X509 *                              scert = NULL;
    int cscinitialized = 0;

    scert = ucert;
    cert_store = X509_STORE_new();
    X509_STORE_set_verify_cb_func(cert_store, proxy_verify_callback);
    if (cert_chain != NULL)
    {
        for (i=0;i<sk_X509_num(cert_chain);i++)
        {
            xcert = sk_X509_value(cert_chain,i);
            if (!scert)
            {
                scert = xcert;
            }
            else
            {
                j = X509_STORE_add_cert(cert_store, xcert);
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
        X509_STORE_CTX_init(&csc,cert_store,scert,NULL);
        cscinitialized = 1;
#if SSLEAY_VERSION_NUMBER >=  0x0090600fL
        /* override the check_issued with our version */
        csc.check_issued = proxy_check_issued;
#endif
        X509_STORE_CTX_set_ex_data(&csc,
                                   PVD_STORE_EX_DATA_IDX, (void *)pvd);
#ifdef X509_V_FLAG_ALLOW_PROXY_CERTS
        X509_STORE_CTX_set_flags(&csc, X509_V_FLAG_ALLOW_PROXY_CERTS);
#endif
        if(!X509_verify_cert(&csc))
        {
            goto err;
        }
    } 
    retval = 1;

err:
    if (cscinitialized) X509_STORE_CTX_cleanup(&csc);
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
    int                                 len;
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
            len = strlen(home) + strlen(X509_DEFAULT_CERT_DIR) + 2;
            default_cert_dir = (char *)malloc(len);
            if (!default_cert_dir)
            {
                PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                goto err;
            }
            sprintf(default_cert_dir, "%s%s%s",
                    home, FILE_SEPERATOR, X509_DEFAULT_CERT_DIR);

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
                len = strlen(globus_location) +
                    strlen(X509_INSTALLED_CERT_DIR)
                    + 2 /* NUL and FILE_SEPERATOR */;

                installed_cert_dir = (char *) malloc(len);
                if  (!installed_cert_dir)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }
                sprintf(installed_cert_dir,
                        "%s%s%s",
                        globus_location,
                        FILE_SEPERATOR,
                        X509_INSTALLED_CERT_DIR);

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
        unsigned long uid;
        uid = getuid();
        len = strlen(DEFAULT_SECURE_TMP_DIR) 
            + strlen(X509_USER_PROXY_FILE) 
            + 64; 
       
        default_user_proxy = (char *) malloc(len);
        if (!default_user_proxy)
        {
            PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
            goto err;
        }
        sprintf(default_user_proxy,"%s%s%s%lu",
                DEFAULT_SECURE_TMP_DIR,
                FILE_SEPERATOR,
                X509_USER_PROXY_FILE,
                uid);

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
                
                len = strlen(home) + strlen(X509_DEFAULT_USER_CERT) + 2;
                default_user_cert = (char *)malloc(len);

                if (!default_user_cert)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                } 

                sprintf(default_user_cert,"%s%s%s",
                        home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT);
                len = strlen(home) + strlen(X509_DEFAULT_USER_KEY) + 2;
                default_user_key = (char *)malloc(len);
                if (!default_user_key)
                {
                    PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                    goto err;
                }
                sprintf(default_user_key, "%s%s%s",
                        home,FILE_SEPERATOR, X509_DEFAULT_USER_KEY);
                                                
                user_cert = default_user_cert;
                user_key = default_user_key;

                /* Support for pkcs12 credentials. */
                {
                  int fd = open(default_user_cert, O_RDONLY);
                  if (fd == -1) {

                    char *certname = NULL;

                    free(default_user_cert);
                    free(default_user_key);
                    

                    certname = getenv("X509_USER_CRED");

                    len = certname ? strlen(certname) + 1 :
                      strlen(home) + strlen(X509_DEFAULT_USER_CERT_P12_GT) + 2;

                    default_user_cert = (char *)malloc(len);

                    if (!default_user_cert) {
                      PRXYerr(PRXYERR_F_INIT_CRED, PRXYERR_R_OUT_OF_MEMORY);
                      goto err;
                    } 

                    if (!certname) {
                      sprintf(default_user_cert,"%s%s%s",
                              home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT_P12);

                      if (checkstat(default_user_cert) != 0)
                        sprintf(default_user_cert,"%s%s%s",
                                home, FILE_SEPERATOR, X509_DEFAULT_USER_CERT_P12_GT);
                    }
                    else
                      strcpy(default_user_cert, certname);

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
        *p_user_cert = strdup(user_cert);
      }
      if (p_user_key && user_key && !(*p_user_key)) {
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
    int                                 (*pw_cb)(),
    BIO *                               bp,
    UNUSED(unsigned long *                     hSession))
{
    int                                 status = -1;
    FILE *                              fp;
    int                                 (*xpw_cb)();

    xpw_cb = pw_cb;
#ifdef WIN32
    if (!xpw_cb)
    {
        xpw_cb = read_passphrase_win32;
    }
#endif

    /* Check arguments */
    if (!bp && !user_cert)
    {
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOCERT_FILE);
      status = PRXYERR_R_PROBLEM_USER_NOCERT_FILE;
        
      ERR_add_error_data(1, "\n        No certificate file found");
      goto err;   
    }

    if (!bp && !strncmp(user_cert,"SC:",3))
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
        if (bp)
        {
            if (PEM_read_bio_X509(bp, certificate,
                                  OPENSSL_PEM_CB(NULL,NULL)) == NULL)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_CERT);
                status = PRXYERR_R_PROCESS_CERT;
                goto err;

            }
        }
        else
        {

            if((fp = fopen(user_cert,"rb")) == NULL)
            {
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
    BIO *                               bp,
    UNUSED(unsigned long *                     hSession))
{
    unsigned long                       error;
    int                                 mismatch = 0;
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
    if (!bp && !user_key)
    {
      PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
      status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;
      
      ERR_add_error_data(1,"\n        No key file found");
      goto err;   
    }

            
    if (!bp && !strncmp(user_key,"SC:",3))
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
        if (bp)
        {
            if (PEM_read_bio_PrivateKey(bp,private_key,
                                        OPENSSL_PEM_CB(xpw_cb,NULL)) == NULL)
            {
                PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
                status = PRXYERR_R_PROCESS_KEY;
                goto err;
            }
        }
        else
        {
            int keystatus;
            if ((fp = fopen(user_key,"rb")) == NULL)
            {
              PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_USER_NOKEY_FILE);
              status = PRXYERR_R_PROBLEM_USER_NOKEY_FILE;

              ERR_add_error_data(2, "\n        File=",user_key);
              goto err;
            }

            /* user key must be owned by the user, and readable
             * only be the user
             */

            if ((keystatus = checkstat(user_key)))
            {
                if (keystatus == 4)
                {
                  status = PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE;
                  PRXYerr(PRXYERR_F_INIT_CRED,
                          PRXYERR_R_USER_ZERO_LENGTH_KEY_FILE);
                }
                else
                {
                    status = PRXYERR_R_PROBLEM_KEY_FILE;
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROBLEM_KEY_FILE);
                }

                ERR_add_error_data(2, "\n        File=", user_key);
                fclose(fp);
                goto err;
            }

            if (PEM_read_PrivateKey(fp,
                                    private_key,
                                    OPENSSL_PEM_CB(xpw_cb,NULL)) == NULL)
            {
                fclose(fp);
                error = ERR_peek_error();
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
                else
                {
                    PRXYerr(PRXYERR_F_INIT_CRED,PRXYERR_R_PROCESS_KEY);
                    ERR_add_error_data(2, "\n        File=", user_key);
                    status = PRXYERR_R_PROCESS_KEY;
                }
                goto err;
            }
            fclose(fp);
        }
    }

    /* 
     * check that the private key matches the certificate
     * Dont want a mixup of keys and certs
     * Will only check rsa type for now. 
     */
    if (ucert)
    {
        ucertpkey =  X509_PUBKEY_get(X509_get_X509_PUBKEY(ucert));
        if (ucertpkey!= NULL  && ucertpkey->type == 
            (*private_key)->type)
        {
            if (ucertpkey->type == EVP_PKEY_RSA)
            {
                /* add in key as random data too */
                if (ucertpkey->pkey.rsa != NULL)
                {
                    if(ucertpkey->pkey.rsa->p != NULL)
                    {
                        RAND_add((void*)ucertpkey->pkey.rsa->p->d,
                                 BN_num_bytes(ucertpkey->pkey.rsa->p),
                                 BN_num_bytes(ucertpkey->pkey.rsa->p));
                    }
                    if(ucertpkey->pkey.rsa->q != NULL)
                    {
                        RAND_add((void*)ucertpkey->pkey.rsa->q->d,
                                 BN_num_bytes(ucertpkey->pkey.rsa->q),
                                 BN_num_bytes(ucertpkey->pkey.rsa->q));
                    }
                }
                if ((ucertpkey->pkey.rsa != NULL) && 
                    (ucertpkey->pkey.rsa->n != NULL) &&
                    ((*private_key)->pkey.rsa != NULL) )
                {
                  if ((*private_key)->pkey.rsa->n != NULL
                      && BN_num_bytes((*private_key)->pkey.rsa->n))
                    {
                        if (BN_cmp(ucertpkey->pkey.rsa->n,
                                   (*private_key)->pkey.rsa->n))
                        {
                            mismatch=1;
                        }
                    }
                    else
                    {
                      (*private_key)->pkey.rsa->n =
                            BN_dup(ucertpkey->pkey.rsa->n);
                      (*private_key)->pkey.rsa->e =
                            BN_dup(ucertpkey->pkey.rsa->e);
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
    newtime = 0;
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
  *(p++)='Z';
  *(p++)='\0';

  if (*str == 'Z') {
    offset=0;
  }
  else {
    if ((*str != '+') && (str[5] != '-')) {
      newtime = 0;
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
  tm.tm_sec  += (buff1[index++]-'0');

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


/**********************************************************************
Function: proxy_password_callback_no_prompt()

Description:
            Function to be passed into SSLeay as a password callback. Simply
      returns an error if called so that user will not be prompted.
        
Parameters:
      buffer - pointer to buffer to be filled in with password
                        size - size of buffer
                        w - XXX I have no idea

Returns:
      -1 always

**********************************************************************/

int PRIVATE
proxy_password_callback_no_prompt(
    UNUSED(char *                              buffer),
    UNUSED(int                                 size),
    UNUSED(int                                 w))
{
    PRXYerr(PRXYERR_F_CB_NO_PW, PRXYERR_R_NO_PROXY);

    return(-1);
}

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



int PRIVATE determine_filenames(char **cacert, char **certdir, char **outfile,
                                 char **certfile, char **keyfile, int noregen)
{
  char *oldoutfile = NULL;

  if (noregen) {
    int modify = 0;

    if(*outfile)
      oldoutfile = *outfile;

    *outfile = NULL;

    if (*certfile == NULL && *keyfile == NULL) 
      modify = 1;

    if (proxy_get_filenames(0, cacert, certdir, outfile, certfile, keyfile))
      goto err;

    if (modify)
      *certfile = *keyfile = *outfile;

    *outfile = oldoutfile;
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
    if(proxy_load_user_cert(certname, cert, callback, NULL, &hSession))
      goto err;

    EVP_set_pw_prompt("Enter GRID pass phrase:");

    if (keyname) {
      if (!strncmp(keyname, "SC:", 3))
        EVP_set_pw_prompt("Enter card pin:");

      if (proxy_load_user_key(key, *cert, keyname, callback, NULL, &hSession))
        goto err;
    }

    if (stack && (strncmp(certname, "SC:", 3) && (!keyname || !strcmp(certname, keyname)))) {
      chain = sk_X509_new_null();
      if (proxy_load_user_proxy(chain, certname, NULL) < 0)
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
    sk_X509_free(chain);
  if (cert)
    X509_free(*cert);
  if (key)
    EVP_PKEY_free(*key);
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
    if (isdigit(r))
      v = r - '0';
    else
      v = 10 + r -'a';
    v <<= 4;

    if (isdigit(s))
      v += s -'0';
    else
      v += 10 + s - 'a';
  }
  return v;
}

static char *reencode_string(char *string, int *len)
{
  char *temp = string;
  char *pos  = string;
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
  char *currentname = buffername;
  unsigned char *currentvalue = buffervalue;
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
