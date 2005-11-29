/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/
/* demos/sign/sign.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* sign-it.cpp  -  Simple test app using SSLeay envelopes to sign data
   29.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* converted to C - eay :-) */

/* reformated a bit and converted to use the more common functions: this was
 * initially written at the dawn of time :-) - Steve.
 */

#include "config.h"
#include <string>

extern "C" {
#include "replace.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>


}

//#include <stdio.h>
//#include <sslutils.h>
#include <new>

//#define EVP_MD_CTX_init
//#define EVP_MD_CTX_cleanup

#define BUFSIZE 4096

bool sign(EVP_PKEY *pkey, const std::string source, std::string &result);
bool verify(EVP_PKEY *key, const std::string data, const std::string signature);

/*
 * Function:
 *   sign(key, data, len, sig_len)
 *
 * Description:
 *   This function signs a blob of data.
 *
 * Parameters:
 *   'key'    - Pointer to the key to be used for signing.
 *   'source' - The data to be signed.
 *   'result' - The signature.
 *
 * Result:
 *   A boolean indicating success or failure.
 */
bool
sign(EVP_PKEY *pkey, const std::string source, std::string &result)
{
  EVP_MD_CTX md_ctx;
  unsigned int sig_len = BUFSIZE;
  bool status = false;
  char *sig_buf;

  try {
    sig_buf = new char[sig_len];
  } catch (std::bad_alloc) {
    return false;
  }

  /* Just load the crypto library error strings,
   * SSL_load_error_strings() loads the crypto AND the SSL ones */
  //  SSL_load_error_strings();
  ERR_load_crypto_strings();

  if (pkey) {
    /* Do the signature */
    EVP_MD_CTX_init(&md_ctx);
    EVP_SignInit   (&md_ctx, EVP_sha1());
    EVP_SignUpdate (&md_ctx, source.data(), source.size());
    if ((EVP_SignFinal (&md_ctx, (unsigned char *)sig_buf, &sig_len, pkey)) == 1) {
      result = std::string(sig_buf,sig_len);
      status = true;
    }
    EVP_MD_CTX_cleanup(&md_ctx);
  }
  delete[] sig_buf;

  return status;
}

/*
 * Function:
 *   verify(key, data, sig_buf, len, sig_len)
 *
 * Description:
 *   This function verifys the signature on a blob of data.
 *
 * Parameters:
 *   'key'       - The key to be used to verify the signature.
 *   'data'      - The data that has been signed.
 *   'signature' - The signature.
 *
 * Result:
 *   A boolean indicating success or failure.
 */
bool
verify(EVP_PKEY *key, const std::string data, const std::string signature)
{
  EVP_MD_CTX     md_ctx;

  if (!key)
    return false;

  /* Just load the crypto library error strings,
   * SSL_load_error_strings() loads the crypto AND the SSL ones */
  //  SSL_load_error_strings();
  ERR_load_crypto_strings();
  
  /* Verify the signature */
  EVP_MD_CTX_init  (&md_ctx);
  EVP_VerifyInit   (&md_ctx, EVP_sha1());
  EVP_VerifyUpdate (&md_ctx, data.data(), data.size());
  int err = EVP_VerifyFinal (&md_ctx, (unsigned char *)signature.data(), signature.size(), key);
  EVP_MD_CTX_cleanup(&md_ctx);
  
  return (err == 1);
}
