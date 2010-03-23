/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
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
#ifndef VOMS_WRITE_H
#define VOMS_WRITE_H
#include "config.h"

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

extern int writeac(const X509 *issuerc, const STACK_OF(X509) *certstack, const X509 *holder, 
		   const EVP_PKEY *pkey, BIGNUM *s, char **c, 
		   const char *t, char **attributes, AC **ac, const char *voname, 
       const char *uri, int valid, int old, int startpast);
#endif
