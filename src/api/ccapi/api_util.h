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

#ifndef VOMS_API_UTIL_H
#define VOMS_API_UTIL_H

extern "C" {
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifdef HAVE_OPENSSL_E_OS_H
#include <openssl/e_os.h>
#else
#ifdef HAVE_OPENSSL_E_OS2_H
#include <openssl/e_os2.h>
#else
#include <openssl/e_os2.h>
#endif
#endif
#include "credentials.h"

#include <netdb.h>
#include <string>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
}

#include "Client.h"

#include "voms_api.h"

#include <iostream>
#include <iomanip>


#ifndef MS_CALLBACK
#define MS_CALLBACK
#endif

static bool check_cert(X509 *cert, verror_type &error, std::string &cdir);
static int MS_CALLBACK cb(int ok, X509_STORE_CTX *ctx);
static bool id_data(std::string &subj, std::string &ca, verror_type &error);
extern bool contact(const std::string &hostname, int port, const std::string &contact,
                    const std::string &command, std::string &buffer, std::string &subject, std::string &ca, verror_type &error);
extern bool retrieve(X509 *cert, STACK_OF(X509) *chain, recurse_type how, 
                     std::string &buffer, std::string &vo, std::string &file, std::string &subject, std::string &ca, verror_type &error);
extern bool verify(std::string message, vomsdata &voms, verror_type &error, std::string vdir, std::string cdir, std::string subject, std::string ca);

#endif
