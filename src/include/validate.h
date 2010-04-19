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
#ifndef VOMS_VALIDATE_H
#define VOMS_VALIDATE_H

#include "newformat.h"
#include <stddef.h>


struct att {
  char *name;
  char *qual;
  char *val;
};

struct att_list {
  char *grantor;
  struct att **attrs;
};

struct full_att {
  struct att_list **list;
};

struct col {
  int siglen;        /*!< The length of the VOMS server signature */
  unsigned char *signature;   /*!< The VOMS server signature */
  char *user;        /*!< The user's DN, as from his certificate */
  char *userca;      /*!< The CA which signed the user's certificate */
  char *server;      /*!< The VOMS server DN, as from its certificate */
  char *serverca;    /*!< The CA which signed the VOMS certificate */
  char *voname;      /*!< The name of the VO to which the VOMS belongs */
  char *uri;         /*!< The URI of the VOMS server */
  char *date1;       /*!< Beginning of validity of the user info */
  char *date2;       /*!< End of validity of the user info */
  int   type;        /*!< The type of data returned */
  struct data **std; /*!< User's characteristics */
  char *custom;      /*!< The data returned by an S command */
  int datalen;
  int version;
  char **compact;    /*!< User's attributes in compact format */
  char *serial;
  struct full_att *atts;
  /* Fields below this line are reserved. */
  char *reserved;
  int reserved2;
  int structtype;
  char *buffer;
  int buflen;
};

extern int validate(X509 *, X509 *, AC *, struct col *, int, time_t);

#define VER_NONE    0x00
#define VER_DATE    0x01
#define VER_TARGETS 0x02
#define VER_KEYID   0x04
#define VER_SIGN    0x08
#define VER_ID      0x10
#define VER_ALL     0xffffffff

#endif
