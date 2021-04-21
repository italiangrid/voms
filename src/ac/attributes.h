/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi    - Valerio.Venturi@cnaf.infn.it
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
#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include "newformat.h"
#include "acerrors.h"
#include "acstack.h"

#ifndef VOMS_MAYBECONST
#if defined(D2I_OF)
#define VOMS_MAYBECONST const
#else
#define VOMS_MAYBECONST
#endif
#endif

typedef struct ACATTRIBUTE {
  ASN1_OCTET_STRING *name;
  ASN1_OCTET_STRING *value;
  ASN1_OCTET_STRING *qualifier;
} AC_ATTRIBUTE;

typedef struct ACATTHOLDER {
  STACK_OF(GENERAL_NAME) *grantor;
  STACK_OF(AC_ATTRIBUTE) *attributes;
} AC_ATT_HOLDER;

typedef struct ACFULLATTRIBUTES {
  STACK_OF(AC_ATT_HOLDER) *providers;
} AC_FULL_ATTRIBUTES;

DECL_STACK(AC_ATTRIBUTE);
DECL_STACK(AC_ATT_HOLDER);
DECL_STACK(AC_FULL_ATTRIBUTES);

DECLARE_ASN1_FUNCTIONS(AC_ATTRIBUTE)
DECLARE_ASN1_FUNCTIONS(AC_ATT_HOLDER)
DECLARE_ASN1_FUNCTIONS(AC_FULL_ATTRIBUTES)
