/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
