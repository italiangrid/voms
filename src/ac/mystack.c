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
#include "config.h"

#include "acstack.h"
#include "newformat.h"
#include "attributes.h"

IMPL_STACK(AC_IETFATTR)
IMPL_STACK(AC_IETFATTRVAL)
IMPL_STACK(AC_ATTR)
IMPL_STACK(AC);
/*
IMPL_STACK(AC_INFO);
IMPL_STACK(AC_VAL);
IMPL_STACK(AC_HOLDER);
IMPL_STACK(AC_ACI);
IMPL_STACK(AC_FORM);
IMPL_STACK(AC_IS);
IMPL_STACK(AC_DIGEST);
IMPL_STACK(AC_TARGETS);
*/
IMPL_STACK(AC_TARGET);
/*
IMPL_STACK(AC_CERTS);
*/
IMPL_STACK(AC_ATTRIBUTE)
IMPL_STACK(AC_ATT_HOLDER)
/*
IMPL_STACK(AC_FULL_ATTRIBUTES)
*/
