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
#ifndef VOMS_FORMAT_H
#define VOMS_FORMAT_H

#include <string>
#include <openssl/pem.h>

/* format.c */
struct collection {
  std::string user;
  std::string userca;
  std::string server;
  std::string serverca;
  std::string voname;
  std::string date1;
  std::string date2;
  int    datalen;
  std::string data;
  std::string uri;
};

extern bool unformat(const std::string data, const EVP_PKEY *key,
		     collection &results);
extern bool format(const std::string data, const std::string user,
		   const std::string userca, const std::string server,
		   const std::string serverca, const EVP_PKEY *key, int valid,
		   const std::string voname, const std::string uri,
		   std::string &formatted);
#endif
