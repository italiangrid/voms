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

#ifndef VOMS_IO_H
#define VOMS_IO_H

#include "config.h"

extern "C" {
#include "replace.h"
#include <time.h>
#include <openssl/ssl.h>
}

#include <string>

extern int do_select(int fd, time_t starttime, int timeout, int wanted);
extern bool do_connect(SSL *ssl, int fd, int timeout,  std::string& error);
extern bool do_write(SSL *ssl, int timeout, const std::string& text, std::string &error);
extern bool do_read(SSL *ssl, int timeout, std::string& output);

#endif
