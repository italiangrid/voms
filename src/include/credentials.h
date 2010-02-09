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

#ifndef VOMS_CREDENTIALS_H
#define VOMS_CREDENTIALS_H

#include <openssl/x509.h>
#include <openssl/evp.h>

extern int globus(int);
extern X509 *get_real_cert(X509 *base, STACK_OF(X509) *stk);
extern char *get_peer_serial(X509 *);

#endif
